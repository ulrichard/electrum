#from PyQt4.Qt import QMessageBox, QDialog, QVBoxLayout, QLabel, QThread, SIGNAL
#import PyQt4.QtCore as QtCore

import electrum
from electrum_gui.qt.util import * 
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.wallet import BIP32_HD_Wallet
from electrum.util import print_error
from electrum_gui.qt.qrtextedit import ShowQRTextEdit
from electrum_gui.qt.qrcodewidget import QRCodeWidget

try:
    import hid
    import json
    import base64
    import hashlib
    import aes
    from ecdsa.ecdsa import generator_secp256k1
    from ecdsa.util import sigencode_der
    DIGIBOX = True
except ImportError as e:
    DIGIBOX = False
    print "Digital Bitbox import error: %s." % e.message


digibox_report_buf_size = 2048

EncodeAES = lambda secret, s: base64.b64encode(aes.encryptData(secret,s))
DecodeAES = lambda secret, e: aes.decryptData(secret, base64.b64decode(e))

def sha256(x):
    return hashlib.sha256(x).digest()

def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return sha256(sha256(x))



# ########################################################################
#
# Electrum plugin functionality
#
class Plugin(BasePlugin):
    
    def __init__(self, config, name):
        BasePlugin.__init__(self, config, name)
        self._is_available = self._init()
        self.handler = None
        ##self.tab_index = None
        self.wallet = None
    
    def _init(self):
        return DIGIBOX
    
     
    def constructor(self, s):
        return DigiboxWallet(s)
     
    
    @hook
    def init_qt(self, gui):
        self.main_gui = gui
        self.tab_index = self.main_gui.main_window.tabs.addTab(digibox_dialog_tab.create_digibox_tab(), _('Digital Bitbox') )

    @hook
    def load_wallet(self, wallet, window):
        self.print_error("load_wallet")
        digibox_dialog_tab.set_wallet(wallet)
        self.wallet = wallet
        self.window = window
        self.wallet.plugin = self
        if self.handler is None:
            self.handler = DigiboxQtHandler(self.window.app)
            #self.handler = DigiboxWaitDialog(self.window.app)
        
        if not self.digibox_is_connected():
            self.wallet.force_watching_only = True
  
    '''
    # moved to sign_transaction
    @hook
    def send_tx(self, tx):
        tx.error = None
        try:
            self.wallet.digibox_sign(tx)
        except Exception as e:
            tx.error = str(e)
    '''
    
    @hook
    def installwizard_load_wallet(self, wallet, window):
        self.load_wallet(wallet, window) 
    
    
    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != 'digibox': 
            return
      
        wallet = DigiboxWallet(storage)
        
        if not self.digibox_is_connected():
            QMessageBox.information(None , _('Error'), _("A Digital Bitbox device is not detected."), _('OK'))
            wizard.restore_or_load()
        
        while True:
            
            action = digibox_dialog_install.restore_or_load()
            if action == None:
                return
            
            if action == 'load_electrum':
                seed = wizard.enter_seed_dialog("Enter a BIP32 seed", None, func=lambda x:True)
                if not seed:
                    continue
                if not wallet.load_electrum(seed):
                    continue
        
            elif action == 'load_sd':
                decrypt, filename = digibox_dialog_install.sd_info()
                if decrypt==None:
                    continue
                if not wallet.load_sd(filename, decrypt):
                    continue
            
            elif action == 'erase':
                wallet.erase_wallet()
                continue

            elif action == 'existing':
                pass


            if wallet.load_wallet():
                return wallet


    def is_available(self):        
        return True ##############################################################################
        if not self.digibox_is_connected():
            return False
        #if not self._is_available:
        #    return False
        #if not self.wallet:
        #    return False
        #if self.wallet.storage.get('wallet_type') != 'digibox':
        #    return False
        return self._is_available
        #return True

    def is_enabled(self):
        return self.is_available()
        #if not self.is_available():
        #    return False
        #if self.wallet.has_seed():
        #    return False
        #return True
    
    def set_enabled(self, enabled):
        self.wallet.storage.put('use_' + self.name, enabled)


    def digibox_is_connected(self):
        d = hid.enumerate(0x03eb, 0x2402)
        if not d:
            return False
        else:
            #hid.free_enumeration(d)
            return True

    

# ########################################################################
#
# Digital Bitbox wallet
#
class DigiboxWallet(BIP32_HD_Wallet):
    wallet_type = 'digibox'
    root_derivation = "m/44'/0'"
    
    def __init__(self, storage):
        BIP32_HD_Wallet.__init__(self, storage)
        self.mpk = None
        self.password = None
        self.has_pass = False
        self.hid_device = None
        self.device_checked = False
        self.wallet_installed = False
        self.force_watching_only = False
        digibox_dialog_wait = self.handler

    def give_error(self, message):
        QMessageBox.warning(QDialog(), _('Warning'), _(message), _('OK'))
        raise Exception(message)                

    def get_action(self):
        if not self.accounts:
            return 'create_accounts'

    def can_sign_xpubkey(self, x_pubkey):
        xpub, sequence = BIP32_Account.parse_xpubkey(x_pubkey)
        return xpub in self.master_public_keys.values()

    def can_create_accounts(self):
        return True

    def can_change_password(self):
        return False

    def is_watching_only(self):
        return self.force_watching_only

    def get_client(self, noPin=False):
        '''
        if not DIGIBOX:
            self.give_error('please install ......')
        aborted = False
        if not self.client or self.client.bad:
            try:
                pass
        return self.client
        '''
        pass


    def check_proper_device(self):
        xpub0 = self.master_public_keys["x/0'"]
        if not self.device_checked:
            try:
                xpub_hw = self.get_public_key("m/44'/0'/0'")
            except Exception, e:
                self.give_error(e)
            self.device_checked = True
            if xpub0 != xpub_hw:
                self.proper_device = False
            else:
                self.proper_device = True
        return self.proper_device
   

    def erase_wallet(self):
        reply = QMessageBox.critical(None, _('Warning'), \
                                    _('This will erase your private keys! Do you want to continue?'), \
                                    _('Cancel'), _('OK'))
        if reply:
            if self.commander('{"reset":"__ERASE__"}', False, False):
                QMessageBox.information(None, _('Information'), _('Erased.'), _('OK'))

        
    def address_id(self, address):
        account_id, (change, address_index) = self.get_address_index(address)
        return "m/44'/0'/%s'/%d/%d" % (account_id, change, address_index)
    
    def create_main_account(self, password=None):
        if self.new_wallet()==None:
            raise Exception('Could not create a new wallet. Exiting.')
            return
        self.load_wallet() 

    def load_wallet(self):
        if self.get_master_public_key():
            self.create_account('Main account', None) #name, empty password
            ret = True
        else:
            ret = False 
        return ret

    def derive_xkeys(self, root, derivation, password):
        derivation = derivation.replace(self.root_name,"m/44'/0'/")
        xpub = self.get_public_key(derivation)
        return xpub, None
    
    def get_private_key(self, address, password):
        return []
     
    def get_public_key(self, keypath, require_pass=False):
        if "x/0'" in self.master_public_keys and keypath=="m/44'/0'":
            return self.master_public_keys["x/0'"]
        
        if "x/1'" in self.master_public_keys and keypath=="m/44'/1'":
            return self.master_public_keys["x/1'"]
        
        msg = '{"xpub": "' + keypath + '"}'; 
        reply = self.commander(msg, require_pass)
        if reply==None:
            return
        if "xpub" in reply:
            return reply["xpub"]
        return

    def get_master_public_key(self):
        try:
            if not self.mpk:
                self.mpk = self.get_public_key("m/44'/0'")
            return self.mpk
        except Exception as e:
            #self.give_error(e.message)        
            return 
        
    def i4b(self, x):
        return pack('>I', x)
    
    def add_keypairs(self, tx, keypairs, password):
        #do nothing
        pass
    
    def decrypt_message(self, pubkey, message, password):
        self.give_error("Not supported")
    
    def sign_message(self, address, message, password):
        # to add
        pass

    def password_set(self):
        try:
                
            # Check if device has been set up by asking for its name.
            # Will return an encryption error if set up.
            # Will ask for a password if not set up.
            msg = '{"name":""}'
            
            self.hid_open()
            self.hid_device.write('\0' + bytearray(msg) + '\0'*(digibox_report_buf_size-len(msg))) 
            
	    r = []
            while len(r) < digibox_report_buf_size:    
                r = r + self.hid_device.read(digibox_report_buf_size)

	    self.hid_close()
            
            r = str(bytearray(r)).rstrip(' \t\r\n\0')
            reply = json.loads(r)
                
            is_set = True
            for key in reply:
                if 'error' in reply[key]:
                    if reply[key]['error'] == 'Please set a password.':
                        is_set = False
                        password, sham = digibox_dialog_password.password_dialog(True, False)
            if is_set:
                sham, password = digibox_dialog_password.password_dialog(True, True)
            
            if not password:
                return False

            if is_set:
                self.password = password
                self.has_pass = True
                return True
            else:
                if self.commander(('{"password":"%s"}' % password), False, False, ""):
                    self.password = password
                    self.has_pass = True
                    #QMessageBox.information(None, _('Information'), _("Password set successfully."), _('OK'))
                    return True
                else:
                    return False

        except IOError as e:
            QMessageBox.critical(None, _('Error'), _(e), _('OK'))
            return False
        finally:
            pass
            #self.hid_close()
        

    def load_electrum(self, seed):
        if self.password_set():
            digibox_dialog_wait.start_wait(_("Loading the mnemonic, please wait."))
            if self.commander(('{"seed":{"source":"%s"}}' % seed), False):
                digibox_dialog_wait.finish_wait()
                return True
            digibox_dialog_wait.finish_wait()
        return False


    def load_sd(self, filename, decrypt):
        if self.password_set():
            msg = '{"seed":{"decrypt":"' + ('yes' if decrypt else 'no') + ('","source":"%s"}}' % filename)
            if self.commander(msg, False):
                return True
        return False


    def new_wallet(self):
        salt = digibox_dialog_install.new_wallet()
        ret = None
        if self.password_set():
            digibox_dialog_wait.start_wait(_("Creating a new wallet, please wait."))
            ret = self.commander('{"seed":{"source":"create","salt":"%s"}}' % salt, False)
            digibox_dialog_wait.finish_wait() 
        return ret 


    def sign_transaction(self, tx, password):
        tx.error = None
        try:
            self.digibox_sign(tx)
        except Exception as e:
            tx.error = str(e)
            print e 
        '''
        # the tx is signed via the send_tx() hook to digibox_sign
        # otherwise the gui wait dialog causes a crash
        if tx.error:
            raise BaseException(tx.error)
        '''
    
    
    # ########################################################################
    #
    # Transaction signing protocol
    #
    def digibox_sign(self, tx):
        try:

            change_keypath = None
            
            for i, txout in enumerate(tx.outputs):
                addr = tx.outputs[i][1]
                if self.is_change(addr):
                    change_keypath = self.address_id(addr)
            
            require_pass = True;
            for i, txin in enumerate(tx.inputs):
                signatures = filter(None, txin['signatures'])
                num = txin['num_sig']
                if len(signatures) == num:
                    # Continue if this txin is complete.
                    continue

                for x_pubkey in txin['x_pubkeys']:
                    print_error("Creating signature for", x_pubkey)
                    ii = tx.inputs[i]['x_pubkeys'].index(x_pubkey)
                    keypath = self.address_id(tx.inputs[i]['address'])
                    if True:
                        for_sig = tx.tx_for_sig(i)
                        msg = '{"sign": {"type":"transaction", "data":"%s", "keypath":"%s", "change_keypath":"%s"} }' % \
                               (for_sig, keypath, change_keypath)
                    else:
                        for_sig = Hash(tx.tx_for_sig(i).decode('hex'))
                        for_sig = for_sig.encode('hex')
                        msg = '{"sign": {"type":"hash", "data":"%s", "keypath":"%s"} }' % \
                               (for_sig, keypath)
           
                    reply = self.commander(msg, require_pass)

                    if reply==None: 
                        raise Exception("Could not sign transaction.")

                    if 'sign' in reply:
                        require_pass = False
                        print_error("Adding signature for", x_pubkey)
                        item = reply['sign']
                        tx.inputs[i]['x_pubkeys'][ii] = item['pubkey']
                        tx.inputs[i]['pubkeys'][ii] = item['pubkey']
                        r = int(item['sig'][:64], 16)
                        s = int(item['sig'][64:], 16)
                        sig = sigencode_der(r, s, generator_secp256k1.order())
                        tx.inputs[i]['signatures'][ii] = sig.encode('hex')
                    else:
                        raise Exception("Could not sign transaction.")
      

        except Exception as e:
            raise Exception(e) 
        else:
            print_error("is_complete", tx.is_complete())
            tx.raw = tx.serialize()
       

    

    # ########################################################################
    #
    # USB HID communication protocol
    #
    def commander(self, msg, require_pass=True, encrypt=True, old_pass=False):
        debug = True
        try:
            reply = None
            
            self.hid_open()
            
            msg_l = json.loads(msg)
        
            # Send message
            if debug:
                print "\n\nSending:"
                print msg
            msg = msg.encode('ascii')
            
            print 'debug 0'
            
            if encrypt:
                # set require_pass = False for non-sensitive commands
                # to avoid asking for the password too often
                if not old_pass==False:
                    self.password = old_pass
                    self.has_pass = False
                elif require_pass or not self.has_pass:
                    new_pass = False
                    sham, self.password = digibox_dialog_password.password_dialog(new_pass)
            
                print 'debug 1'
                
                if not self.password==None:
                    if len(self.password):
                        secret = Hash(self.password)
                        msg = EncodeAES(secret,msg)
            
            wait_msg = "Processing command, please wait."
            '''
            if 'password' in msg_l:
                wait_msg = "Press the touch button to change the password."
            if 'seed' in msg_l:
                wait_msg = "Press the touch button to create a wallet."
            '''
            if 'reset' in msg_l:
                wait_msg = "Press the touch button 3 times to erase."

            print 'debug A'
            
            digibox_dialog_wait.start_wait(_(wait_msg))
            self.hid_device.write('\0' + bytearray(msg) + '\0' * (digibox_report_buf_size - len(msg))) 
	    r = []
            while len(r) < digibox_report_buf_size:    
	        r = r + self.hid_device.read(digibox_report_buf_size)
            r = str(bytearray(r)).rstrip(' \t\r\n\0')
            reply = json.loads(r)
            digibox_dialog_wait.finish_wait()
            
            if debug:
                print "Reply str:\n" + r
                print "Reply json:\n>>"
                print reply
                print "<< end json"
            
            if 'echo' in reply:
                echo = reply["echo"]
                #echo = DecodeAES(secret, ''.join(reply["echo"]))
                if debug:
                    print "Echo:  " + echo
                digibox_dialog_wait.start_wait_echo(echo)
                self.hid_device.write('\0' + bytearray(msg) + '\0' * (digibox_report_buf_size - len(msg))) 
	        r = []
                while len(r) < digibox_report_buf_size:    
	            r = r + self.hid_device.read(digibox_report_buf_size)
                    
		r = str(bytearray(r)).rstrip(' \t\r\n\0')
                reply = json.loads(r)
                digibox_dialog_wait.finish_wait()
            
            
            error = False
            for key in reply:
                if 'error' in reply[key]:
                    self.has_pass = False
                    QMessageBox.critical(None, _('Error'), _(reply[key]['error']), _('OK'))
                    error = True
            
            if 'ciphertext' in reply and not self.password==None and not error:
                if len(self.password):
                    self.has_pass = True
                    reply = DecodeAES(secret, ''.join(reply["ciphertext"]))
                    if debug:
                        print "Reply decrypted:  "
                        print reply
                    reply = json.loads(reply)
                    
                    if '2FA' in reply:
                        pin = line_dialog(None, _('Digital Bitbox'), \
                                _('Enter the lock code from the 2FA device') + ':', \
                                _('OK'), None)
                        reply = DecodeAES(Hash(pin), ''.join(reply["2FA"]))
                        reply = json.loads(reply)
                        if debug:
                            print "Reply decrypted (2FA):  "
                            print reply

                    for key in reply:
                        if 'error' in reply[key]:
                            QMessageBox.critical(None, _('Error'), _(reply[key]['error']), _('OK'))
                            error = True
            
            if error:
                reply = None
                raise Exception('Error returned') 
            
        except IOError as e:
            QMessageBox.critical(None, _('Error'), _("Could not access the Digital Bitbox."), _('OK'))
        except Exception as e:
            print "Exception:  " + e
        except:
            print "Unknown exception"
        finally:
            if digibox_dialog_wait.waiting:
                digibox_dialog_wait.finish_wait()
            self.hid_close()
            return reply

    
    def hid_open(self):
        self.hid_device = hid.device()
        self.hid_device.open(0x03eb, 0x2402)


    def hid_close(self):
        self.hid_device.close()



# ########################################################################
#
# PyQT control panel tab
#
class DigiboxTab(object):
    def set_wallet(self, wallet):
        self.wallet = wallet
    
    def create_digibox_tab(self):
        w = QWidget()
        # w.setDisabled(True)

        grid = QGridLayout(w)
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(3, 300)
        grid.setColumnStretch(6, 1)
        grid.setRowStretch(8, 1)
       
        '''
        # touch button
        touch_ql = QLabel(_("Touch button"))
        touch_ql_timeout   = QLabel(_("timeout [sec]"))
        touch_ql_thresh    = QLabel(_("threshold"))
        touch_qsb_timeout  = QSpinBox()
        touch_qsb_thresh   = QSpinBox()
        touch_qsb_thresh.setMaximum(10000)
        touch_qsb_thresh.setValue(50)
        touch_qsb_timeout.setValue(10)
        def touch_button_push():
            self.wallet.commander('{"touchbutton":{"threshold":"%s", "timeout":"%s"}}' % (\
                                      str(touch_qsb_thresh.text()), str(touch_qsb_timeout.text()) ), False)
        touch_qpb = EnterButton(_("Update"), touch_button_push)
        '''

        # create / export verification password
        verifypw_ql = QLabel(_("Verification\npassword"))
        verifypw_ql.setAlignment(Qt.AlignCenter)
        def verifypw_create_button_push():
            r = self.wallet.commander('{"verifypass":"create"}', False)
        def verifypw_export_button_push():
            r = self.wallet.commander('{"verifypass":"export"}', False)
        verifypw_create_qpb = EnterButton(_("Create"), verifypw_create_button_push)
        verifypw_export_qpb = EnterButton(_("Export"), verifypw_export_button_push)

        # list / erase uSD files
        sdcard_ql = QLabel(_("SD card"))
        sdcard_ql.setAlignment(Qt.AlignCenter)
        def sdcard_list_button_push():
            r = self.wallet.commander('{"backup":"list"}', False)
            if r:
                self.show_text_qr("SD card files", r["sd_list"])
        def sdcard_erase_button_push():
            r = self.wallet.commander('{"backup":"erase"}', False)
        sdcard_list_qpb = EnterButton(_("List files"), sdcard_list_button_push)
        sdcard_erase_qpb = EnterButton(_("Erase files"), sdcard_erase_button_push)
        

        # get xpub
        xpub_default_keypath = "m/44'/0'/0'"
        xpub_ql = QLabel(_("BIP32 keypath"))
        xpub_qle = QLineEdit()
        xpub_qle.setPlaceholderText(_(xpub_default_keypath))
        def xpub_button_push():
            xpub = self.wallet.get_public_key(str(xpub_qle.text()) if not xpub_qle.text()=="" else xpub_default_keypath)
            if xpub:
                self.show_text_qr("Extended Public Key", xpub)
        xpub_qpb = EnterButton(_("Get xpub"), xpub_button_push)
        
        
        # name
        name_ql = QLabel(_(""))
        name_qle = QLineEdit()
        name_qle.setEnabled(False)
        def name_button_push():
            if name_qpb.text()=="Get name":
                name = ""
            else:
                name = line_dialog(None, _('Digital Bitbox'), _('Enter new name') + ':', _('OK'), None)
                if name=="" or name==None:
                    return
            name = self.wallet.commander(('{"name":"%s"}' % name), False)
            if name:
                name_ql.setText(_(name["name"]))
                name_qpb.setText(_("Rename"))
        name_qpb = EnterButton(_("Get name"), name_button_push)


        # led
        def led_button_push():
            r = self.wallet.commander('{"led":"toggle"}', False)
        led_qpb = EnterButton(_("Toggle LED"), led_button_push)


        # lock
        def lock_button_push():
            r = self.wallet.commander('{"device":"lock"}', False)
        lock_qpb = EnterButton(_("Lock"), lock_button_push)


        # backup
        def backup_button_push():
            encrypt, filename = digibox_dialog_install.sd_info()
            if filename==None or filename=="":
                return
            enc = 'yes' if encrypt else 'no'
            if self.wallet.commander('{"backup":{"encrypt":"%s", "filename":"%s"}}' % (enc, filename), False):
                QMessageBox.information(None, _('Information'), _("Backup successful."), _('OK'))
        backup_qpb = EnterButton(_("Backup seed"), backup_button_push)
       

        # random number
        def random_button_push():
            r = self.wallet.commander('{"random":"pseudo"}', False)
            if r:
                self.show_text_qr("Random number", r["random"])
        random_qpb = EnterButton(_("Random #"), random_button_push)
       

        # new password
        def password_button_push():
            password, old_password = digibox_dialog_password.password_dialog(True)
            password = '' if password==None else password
            old_password = '' if old_password==None else old_password
            if not self.wallet.commander(('{"password":"%s"}' % password), False, True, old_password)==None:
                pass
                #QMessageBox.information(None, _('Information'), _("Password set successfully."), _('OK'))
        password_qpb = EnterButton(_("Set password"), password_button_push)


        # reset
        def reset_button_push():
            self.wallet.erase_wallet()
        reset_qpb = EnterButton(_("Erase"), reset_button_push)


        # command line
        cmd_ql = QLabel(_("Command line:"))
        cmd_ql_r = QLabel(_(""))
        cmd_qle = QLineEdit()
        cmd_qle.setPlaceholderText(_("Enter a JSON command"))
        def cmd_button_push():
            cmd = str(cmd_qle.text()) 
            r = None
            if len(cmd):
                r = self.wallet.commander(cmd, False)
            if r:
                cmd_ql_r.setText(_(json.dumps(r)))
        cmd_qpb = EnterButton(_("Send"), cmd_button_push)
        

        grid.addWidget(name_ql,      1, 0, 1, 2)
        grid.addWidget(name_qpb,     2, 0, 1, 1)
        
        grid.addWidget(led_qpb,      2, 1, 1, 1)
        grid.addWidget(random_qpb,   3, 1, 1, 1)
        grid.addWidget(password_qpb, 4, 1, 1, 1)
        grid.addWidget(reset_qpb,    5, 1, 1, 1)
        grid.addWidget(lock_qpb,     6, 1, 1, 1)
        
        grid.addWidget(sdcard_ql,           1, 5, 1, 1)
        grid.addWidget(sdcard_list_qpb,     2, 5, 1, 1)
        grid.addWidget(sdcard_erase_qpb,    3, 5, 1, 1)
        grid.addWidget(backup_qpb,          4, 5, 1, 1)
        
        grid.addWidget(verifypw_ql,         1, 6, 1, 1)
        grid.addWidget(verifypw_create_qpb, 2, 6, 1, 1)
        grid.addWidget(verifypw_export_qpb, 3, 6, 1, 1)
        verifypw_create_qpb.setMaximumWidth(100) 
        verifypw_export_qpb.setMaximumWidth(100) 

        
        
        '''
        grid.addWidget(touch_ql,           1, 4, 1, 1)
        grid.addWidget(touch_qsb_timeout,  1, 5, 1, 1)
        grid.addWidget(touch_ql_timeout,   1, 6, 1, 1)
        grid.addWidget(touch_qsb_thresh,   2, 5, 1, 1)
        grid.addWidget(touch_ql_thresh,    2, 6, 1, 1)
        grid.addWidget(touch_qpb,          3, 6, 1, 1)
        
        grid.addWidget(xpub_ql,    5, 4, 1, 1)
        grid.addWidget(xpub_qle,   5, 5, 1, 1)
        grid.addWidget(xpub_qpb,   5, 6, 1, 1)
        
        grid.addWidget(cmd_ql,     8, 0, 1, 1)
        grid.addWidget(cmd_ql_r,   9, 1, 1, 5)
        grid.addWidget(cmd_qle,    8, 1, 1, 5)
        grid.addWidget(cmd_qpb,    8, 6, 1, 1)
        '''
         
        w.setLayout(grid)
        return w


    def show_text_qr(self, title, data):
        dialog = QDialog()
        dialog.setModal(1)
        dialog.setWindowTitle(_(title))

        vbox = QVBoxLayout()
       
        qr_text = ShowQRTextEdit(text=data)
        qr_text.setMaximumHeight(170)
        qr_text.selectAll()    # for easy copying
        vbox.addWidget(qr_text)
        vbox.addLayout(Buttons(CloseButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()
    


# ########################################################################
#
# PyQT install window
#
class DigiboxInstallDialog(QThread):

    def __init__(self):
        QThread.__init__(self)
        self.waiting = False

    def set_layout(self, layout):
        w = QWidget()
        w.setLayout(layout)
        self.d.stack.addWidget(w)
        self.d.stack.setCurrentWidget(w)

    def gui_setup(self):
        self.d = QDialog()
        self.d.setMinimumSize(575, 400)
        self.d.setMaximumSize(575, 400)
        self.d.stack = QStackedLayout()
        self.d.setWindowTitle('Digital Bitbox')
        self.d.connect(self.d, SIGNAL('accept'), self.d.accept)
        self.d.stack = QStackedLayout()
        self.d.setLayout(self.d.stack)
    
    def gui_finish(self, vbox):
        vbox.addStretch(1)
        
        b = OkButton(self.d)
        c = CancelButton(self.d)
        vbox.addLayout(Buttons(c, b))
        #vbox.addLayout(Buttons(CancelButton(self.d), OkButton(self.d, _('Next'))))
        #vbox.addLayout(Buttons(CancelButton(self.d), OkButton(self.d)))
        self.set_layout(vbox)
        self.d.show()
        self.d.raise_()

    def restore_or_load(self):
        self.gui_setup()
        main_label = QLabel(_("A Digital Bitbox is connected."))

        gb1 = QGroupBox(_("What do you want to do?"))
        b1 = QRadioButton(gb1)
        b2 = QRadioButton(gb1)
        b3 = QRadioButton(gb1)
        b4 = QRadioButton(gb1)
        b1.setText(_("Import an existing wallet on the device into Electrum"))
        b2.setText(_("Create a new wallet on the device by entering a seed in Electrum"))
        b3.setText(_("Load a backup wallet from the micro SD card onto the device"))
        b4.setText(_("Erase the device and its password"))
        
        group1 = QButtonGroup()
        group1.addButton(b1)
        group1.addButton(b2)
        group1.addButton(b3)
        group1.addButton(b4)
        b1.setChecked(True)
        
        vbox = QVBoxLayout()
        vbox.addWidget(main_label)
        vbox.addWidget(gb1)
        vbox.addWidget(b1)
        vbox.addWidget(b2)
        vbox.addWidget(b3)
        vbox.addWidget(b4)

        self.gui_finish(vbox)
        
        if not self.d.exec_():
            return None

        if b1.isChecked():
            action = 'existing'      
        elif b2.isChecked():
            action = 'load_electrum' 
        elif b3.isChecked():
            action = 'load_sd'       
        elif b4.isChecked():
            action = 'erase'       
        else:
            action = None
        return action

    def sd_info(self):
        self.gui_setup()
        main_label = QLabel(_("Please enter the micro SD backup file information."))

        gb1 = QGroupBox(_("Is the file encrypted?"))
        b1 = QRadioButton(gb1)
        b2 = QRadioButton(gb1)
        b1.setText(_("yes (the Electrum password will be used for decryption)"))
        b2.setText(_("no"))
        l  = QLabel(_("\n"))
        
        group1 = QButtonGroup()
        group1.addButton(b1)
        group1.addButton(b2)
        b2.setChecked(True)
        
        gb2 = QGroupBox(_("Enter the file name"))
        fn = QLineEdit()
        fn.setMaximumWidth(200)

        vbox = QVBoxLayout()
        vbox.addWidget(main_label)
        vbox.addWidget(l)
        vbox.addWidget(gb1)
        vbox.addWidget(b1)
        vbox.addWidget(b2)
        vbox.addWidget(l)
        vbox.addWidget(gb2)
        vbox.addWidget(fn)
        
        self.gui_finish(vbox)

        if not self.d.exec_():
            return None, None

        decrypt = True if b1.isChecked() else False
        filename = "%s" % fn.text()
        return decrypt, filename

    def new_wallet(self):
        self.gui_setup()

        ql2 = QLabel(_("Enter an optional BIP32 passphase (i.e. the salt). Otherwise leave empty."))
        gb2 = QGroupBox()
        gb3 = QGroupBox(_("* Note that the passphrase is NOT saved on the Digital Bitbox."))
        gb4 = QGroupBox(_("* Be sure to remember it if set!"))
        fn = QLineEdit()
        fn.setMaximumWidth(200)

        vbox = QVBoxLayout()
        vbox.addWidget(ql2)
        vbox.addWidget(fn)
        vbox.addWidget(gb3)
        vbox.addWidget(gb4)
        
        self.gui_finish(vbox)

        if not self.d.exec_():
            return None

        salt = "%s" % fn.text()
        return salt


# ########################################################################
#
# PyQT password dialog
#
class DigiboxPasswordDialog(QThread):
    def __init__(self):
        QThread.__init__(self)


    def make_password_dialog(self, msg, new_pass, old_pass):
        
        self.d.pw = QLineEdit()
        self.d.pw.setEchoMode(2)
        self.d.new_pw = QLineEdit()
        self.d.new_pw.setEchoMode(2)
        self.d.conf_pw = QLineEdit()
        self.d.conf_pw.setEchoMode(2)

        vbox = QVBoxLayout()
        label = QLabel(msg)
        label.setWordWrap(True)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 70)
        grid.setColumnStretch(1,1)

        logo = QLabel()
        lockfile = ":icons/lock.png"
        logo.setPixmap(QPixmap(lockfile).scaledToWidth(36))
        logo.setAlignment(Qt.AlignCenter)

        grid.addWidget(logo,  0, 0)
        grid.addWidget(label, 0, 1, 1, 2)
        vbox.addLayout(grid)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 250)
        grid.setColumnStretch(1,1)

        if old_pass:
            grid.addWidget(QLabel(_('Password')), 0, 1)
            grid.addWidget(self.d.pw, 0, 2)
        if new_pass:
            grid.addWidget(QLabel(_('New Password') if new_pass else _('Password')), 1, 1)
            grid.addWidget(self.d.new_pw, 1, 2)
            grid.addWidget(QLabel(_('Confirm Password')), 2, 1)
            grid.addWidget(self.d.conf_pw, 2, 2)

        vbox.addLayout(grid)

        #Password Strength Label
        #self.d.pw_strength = QLabel()
        #grid.addWidget(self.d.pw_strength, 3, 0, 1, 2)
        #self.d.new_pw.textChanged.connect(lambda: update_password_strength(self.d.pw_strength, self.d.new_pw.text()))

        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self.d), OkButton(self.d)))
        return vbox


    def run_password_dialog(self):

        if not self.d.exec_():
            return False, None, None

        password = str(self.d.pw.text()) 
        new_password = str(self.d.new_pw.text())
        new_password2 = str(self.d.conf_pw.text())

        if new_password != new_password2:
            QMessageBox.warning(None, _('Error'), _('Passwords do not match'), _('OK'))
            return self.run_password_dialog()

        if not new_password:
            new_password = None

        return True, password, new_password


    def password_dialog(self, new_pass=False, old_pass=True):
        msg = _("Please enter your password")
        print 'debug P'
        
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setLayout( self.make_password_dialog(msg, new_pass, old_pass) )

        print 'debug P'
        
        confirmed, old_password, new_password = self.run_password_dialog()
        if not confirmed:
            if new_pass:
                QMessageBox.warning(None, _('Error'), _("Password not changed"), _('OK'))
            raise Exception("Password not set")
            return None, None
        return new_password, old_password 

    

# ########################################################################
#
# PyQT waiting windows
#
#class DigiboxWaitDialog:
class DigiboxQtHandler:
    
    def __init__(self, win):
        #QThread.__init__(self)
        self.waiting = False
        
        self.win = win
        self.win.connect(win, SIGNAL('digibox_done'), self.finish_wait)
        self.win.connect(win, SIGNAL('message_dialog'), self.start_wait)
        self.win.connect(win, SIGNAL('message_dialog'), self.start_wait_echo)
        #self.win.connect(win, SIGNAL('digibox_done'), self.dialog_stop)
        #self.win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        #self.win.connect(win, SIGNAL('pin_dialog'), self.pin_dialog)
        #self.win.connect(win, SIGNAL('passphrase_dialog'), self.passphrase_dialog)
        self.done = threading.Event()

    '''
    def stop(self):
        self.win.emit(SIGNAL('digibox_done'))

    def show_message(self, msg):
        self.message = msg
        self.win.emit(SIGNAL('message_dialog'))

    def message_dialog(self):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('Please Check Trezor Device')
        self.d.setWindowFlags(self.d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        l = QLabel(self.message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.d.show()
    '''

    def start_wait(self, message):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('Digital Bitbox')
        self.d.setWindowFlags(Qt.WindowStaysOnTopHint)
        l = QLabel(message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.d.show()
        if not self.waiting:
            self.waiting = True
            #self.d.connect(digibox_dialog_install, SIGNAL('digibox_done'), self.finish_wait)
            #self.finish_wait() 

    def start_wait_echo(self, data):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle(_("Digital Bitbox verification"))
        self.d.setWindowFlags(Qt.WindowStaysOnTopHint)
        
        vbox = QVBoxLayout(self.d)
        
        text0 = QLabel(_("Verification QR code:"))
        text1 = QLabel(_("Push the touch button to continue."))
        
        qrw = QRCodeWidget(data)
        
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        vbox.addWidget(text0)
        vbox.addWidget(qrw, 1)
        vbox.addWidget(text1)

        vbox.addLayout(hbox)
        self.d.show()
        if not self.waiting:
            self.waiting = True
            self.d.connect(digibox_dialog_wait, SIGNAL('qr_done'), self.finish_wait)
        
    def finish_wait(self):
        self.d.hide()
        self.waiting = False
        self.win.emit(SIGNAL('digibox_done'))



if DIGIBOX:
    digibox_dialog_tab = DigiboxTab()
    #digibox_dialog_wait = DigiboxWaitDialog()
    #digibox_dialog_wait = DigiboxQtHandler()
    digibox_dialog_install = DigiboxInstallDialog()
    digibox_dialog_password = DigiboxPasswordDialog()




