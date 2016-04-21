from .plugin import CaseWallet

from electrum.plugins import BasePlugin, hook
from electrum_gui.qt.util import WaitingDialog, EnterButton, WindowModalDialog
from electrum.util import print_msg, print_error
from electrum.i18n import _

from PyQt4.QtGui import *
from PyQt4.QtCore import *


#class Plugin(qt_plugin_class(TrezorPlugin)):
#    icon_file = ":icons/trezor.png"

class Plugin(BasePlugin):
    wallet_class = CaseWallet

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    def is_available(self):
        return True

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Case Wallet Settings"))

        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('xpub1: ')), 0, 0)
        layout.addWidget(QLabel(_('xpub2: ')), 0, 1)
        layout.addWidget(QLabel(_('xpub3: ')), 0, 2)

        edit1 = QEdit()
        edit2 = QEdit()
        edit3 = QEdit()

        layout.addWidget(edit1, 0, 1)
        layout.addWidget(edit2, 1, 1)
        layout.addWidget(edit3, 2, 1)

        ok_button = QPushButton(_("OK"))
        ok_button.clicked.connect(d.accept)
        layout.addWidget(ok_button, 1, 1)

        return bool(d.exec_())
