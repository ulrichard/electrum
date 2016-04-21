from electrum.i18n import _

fullname = 'CASE Wallet'
description = _('Provides a view only wallet for the CASE hardware wallet')
requires_wallet_type = ['2of3_case']
registers_wallet_type = ('hardware', '2of3_case', _("CASE wallet"))
available_for = ['qt', 'cmdline']

