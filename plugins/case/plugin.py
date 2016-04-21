from electrum.wallet import Multisig_Wallet
from electrum.account import Multisig_Account
from electrum.i18n import _

class Case_Account(Multisig_Account):

    def __init__(self, v):
        self.m = 2
        Multisig_Account.__init__(self, v)

#    def get_pubkeys(self, for_change, n):
#        return self.get_pubkey(for_change, n)

    def derive_pubkeys(self, for_change, n):
        return map(lambda x: self.derive_pubkey_from_xpub(x, for_change, n), self.get_master_pubkeys())

#    def redeem_script(self, for_change, n):
#        pubkeys = self.get_pubkeys(for_change, n)
#        return Transaction.multisig_script(sorted(pubkeys), self.m)

    def derive_pubkey_from_xpub(self, xpub, for_change, n):
        _, _, _, c, cK = deserialize_xkey(xpub)
        for i in [for_change, n]:
            cK, c = CKD_pub(cK, c, i)
        return cK.encode('hex')

    def pubkeys_to_address(self, pubkeys):
        redeem_script = Transaction.multisig_script(pubkeys, self.m)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return address

    def get_type(self):
        return _('Multisig %d of %d Case' % (self.m, len(self.xpub_list)))

class CaseWallet(Multisig_Wallet):
    def __init__(self, storage):
        Multisig_Wallet.__init__(self, storage)
        self.wallet_type = storage.get('wallet_type')
        self.m = 2
        self.n = 3

    def load_accounts(self):
        self.accounts = {}
        d = self.storage.get('accounts', {})
        v = d.get('0')
        if v:
            self.accounts = {'0': Case_Account(v)}


