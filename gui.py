import sys
import os
import json
import html
import hashlib
import threading
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QCheckBox,
    QTextEdit, QFileDialog, QMessageBox, QFrame, QProgressBar, QInputDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont
from crypto_backend import FileEncryptor


class DropLineEdit(QLineEdit):
    """QLineEdit supporting drag-and-drop of files or directories."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            local_path = urls[0].toLocalFile()
            if local_path:
                self.setText(os.path.normpath(local_path))
                event.acceptProposedAction()
                return
        super().dropEvent(event)


class WorkerSignals(QObject):
    log_signal = pyqtSignal(str)
    toggle_ui_signal = pyqtSignal(bool)
    clear_inputs_signal = pyqtSignal(str)
    overwrite_request = pyqtSignal(str, object, object)
    passphrase_request = pyqtSignal(str, object, object)
    progress_signal = pyqtSignal(int, int)


class SecureVaultPyQt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.encryptor = FileEncryptor()
        self.signals = WorkerSignals()
        self.cancel_event = threading.Event()

        self._attempts_lock = threading.Lock()
        self._attempts_file = os.path.join(os.path.expanduser("~"), ".securevault_attempts.json")
        self.failed_attempts = self._load_failed_attempts()

        self.signals.log_signal.connect(self.log)
        self.signals.toggle_ui_signal.connect(self.toggle_ui)
        self.signals.clear_inputs_signal.connect(self.clear_inputs)
        self.signals.overwrite_request.connect(self.prompt_overwrite_sync)
        self.signals.passphrase_request.connect(self.prompt_passphrase_sync)
        self.signals.progress_signal.connect(self.update_progress)

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("SecureVault - Enterprise PKI Edition")
        self.setMinimumSize(680, 780)
        self.resize(700, 840)
        self.apply_theme()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(12)

        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 10))
        main_layout.addWidget(self.tabs)

        self.init_encrypt_tab()
        self.init_decrypt_tab()
        self.init_rsa_tab()

        # Progress bar & cancel control
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Idle (%p%)")
        progress_layout.addWidget(self.progress_bar)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setStyleSheet(
            "QPushButton { background-color: #dc2626; } QPushButton:hover { background-color: #b91c1c; }"
        )
        self.btn_cancel.clicked.connect(self.request_cancel)
        progress_layout.addWidget(self.btn_cancel)
        main_layout.addLayout(progress_layout)

        console_label = QLabel("Activity Log Console:")
        console_label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        main_layout.addWidget(console_label)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        self.console.setFixedHeight(140)
        main_layout.addWidget(self.console)

        self.center_window()
        self.log("SecureVault PKI Engine initialized. System ready.")

    def apply_theme(self):
        is_dark = True
        try:
            import winreg
            registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            is_dark = value == 0
        except Exception:
            pass

        if is_dark:
            self.setStyleSheet("""
                QMainWindow { background-color: #121214; }
                QTabWidget::pane { border: 1px solid #27272a; border-radius: 8px; background-color: #1c1c1f; }
                QTabBar::tab { background: #121214; color: #a1a1aa; padding: 10px 20px; border-top-left-radius: 6px; border-top-right-radius: 6px; }
                QTabBar::tab:selected { background: #1c1c1f; color: #ffffff; font-weight: bold; }
                QLabel { color: #e4e4e7; font-family: 'Segoe UI'; }
                QLineEdit { background-color: #27272a; color: #ffffff; border: 1px solid #3f3f46; border-radius: 5px; padding: 6px; font-size: 13px; }
                QLineEdit:focus { border: 1px solid #3b82f6; }
                QPushButton { background-color: #2563eb; color: #ffffff; border: none; border-radius: 5px; padding: 8px 14px; font-weight: bold; font-family: 'Segoe UI'; }
                QPushButton:hover { background-color: #1d4ed8; }
                QPushButton:disabled { background-color: #3f3f46; color: #a1a1aa; }
                QCheckBox { color: #e4e4e7; font-family: 'Segoe UI'; }
                QTextEdit { background-color: #09090b; color: #4ade80; border: 1px solid #27272a; border-radius: 6px; padding: 5px; }
                QProgressBar { border: 1px solid #3f3f46; border-radius: 5px; background-color: #27272a; color: #ffffff; text-align: center; height: 22px; }
                QProgressBar::chunk { background-color: #2563eb; border-radius: 4px; }
                QFrame[frameShape="4"] { color: #3f3f46; }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow { background-color: #f4f4f5; }
                QTabWidget::pane { border: 1px solid #e4e4e7; border-radius: 8px; background-color: #ffffff; }
                QTabBar::tab { background: #e4e4e7; color: #71717a; padding: 10px 20px; border-top-left-radius: 6px; border-top-right-radius: 6px; }
                QTabBar::tab:selected { background: #ffffff; color: #09090b; font-weight: bold; }
                QLabel { color: #09090b; font-family: 'Segoe UI'; }
                QLineEdit { background-color: #ffffff; color: #09090b; border: 1px solid #d4d4d8; border-radius: 5px; padding: 6px; font-size: 13px; }
                QLineEdit:focus { border: 1px solid #2563eb; }
                QPushButton { background-color: #2563eb; color: #ffffff; border: none; border-radius: 5px; padding: 8px 14px; font-weight: bold; font-family: 'Segoe UI'; }
                QPushButton:hover { background-color: #1d4ed8; }
                QPushButton:disabled { background-color: #e4e4e7; color: #a1a1aa; }
                QCheckBox { color: #09090b; font-family: 'Segoe UI'; }
                QTextEdit { background-color: #fafafa; color: #16a34a; border: 1px solid #e4e4e7; border-radius: 6px; padding: 5px; }
                QProgressBar { border: 1px solid #d4d4d8; border-radius: 5px; background-color: #e4e4e7; color: #09090b; text-align: center; height: 22px; }
                QProgressBar::chunk { background-color: #2563eb; border-radius: 4px; }
                QFrame[frameShape="4"] { color: #e4e4e7; }
            """)

    def center_window(self):
        frame_gm = self.frameGeometry()
        screen_obj = QApplication.primaryScreen()
        if screen_obj is not None:
            screen_center = screen_obj.geometry().center()
            frame_gm.moveCenter(screen_center)
            self.move(frame_gm.topLeft())
        else:
            self.move(100, 100)

    def _create_password_field(self, placeholder: str = ""):
        row = QHBoxLayout()
        field = QLineEdit()
        field.setEchoMode(QLineEdit.EchoMode.Password)
        if placeholder:
            field.setPlaceholderText(placeholder)
        btn_toggle = QPushButton("Show")
        btn_toggle.setCheckable(True)
        btn_toggle.setFixedWidth(65)

        def on_toggle(checked: bool):
            field.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
            btn_toggle.setText("Hide" if checked else "Show")

        btn_toggle.toggled.connect(on_toggle)
        row.addWidget(field)
        row.addWidget(btn_toggle)
        return row, field

    # --- TAB 1: LOCAL ENCRYPT ---
    def init_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        layout.addWidget(QLabel("Target File or Folder Path (drag & drop supported):"))
        target_h_layout = QHBoxLayout()
        self.enc_target_input = DropLineEdit()
        target_h_layout.addWidget(self.enc_target_input)

        btn_file = QPushButton("File")
        btn_file.clicked.connect(lambda *args: self.browse_path(self.enc_target_input, "file"))
        btn_folder = QPushButton("Folder")
        btn_folder.clicked.connect(lambda *args: self.browse_path(self.enc_target_input, "folder"))
        target_h_layout.addWidget(btn_file)
        target_h_layout.addWidget(btn_folder)
        layout.addLayout(target_h_layout)

        layout.addWidget(QLabel("Custom Destination (Optional):"))
        out_h_layout = QHBoxLayout()
        self.enc_output_input = DropLineEdit()
        self.enc_output_input.setPlaceholderText("Auto-generates next to target if left blank...")
        out_h_layout.addWidget(self.enc_output_input)

        btn_out_browse = QPushButton("Save As")
        btn_out_browse.clicked.connect(lambda *args: self.browse_save_path(self.enc_output_input))
        out_h_layout.addWidget(btn_out_browse)
        layout.addLayout(out_h_layout)

        layout.addWidget(QLabel("Master Password:"))
        pwd_row, self.enc_pass_input = self._create_password_field()
        self.enc_pass_input.textChanged.connect(self._update_password_strength)
        layout.addLayout(pwd_row)

        strength_row = QHBoxLayout()
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setFixedHeight(14)
        self.strength_bar.setTextVisible(False)
        self.strength_label = QLabel("Strength: Empty")
        self.strength_label.setFont(QFont("Segoe UI", 8))
        strength_row.addWidget(self.strength_bar, 1)
        strength_row.addWidget(self.strength_label, 1)
        layout.addLayout(strength_row)

        layout.addWidget(QLabel("Confirm Password:"))
        conf_row, self.enc_conf_input = self._create_password_field()
        layout.addLayout(conf_row)

        self.shred_checkbox = QCheckBox("Securely shred original item after system lock")
        layout.addWidget(self.shred_checkbox)

        layout.addStretch()

        self.btn_lock = QPushButton("LOCAL LOCK")
        self.btn_lock.setFixedHeight(45)
        self.btn_lock.clicked.connect(self.start_encryption_thread)
        layout.addWidget(self.btn_lock)

        self.tabs.addTab(tab, "Local Encrypt")

    # --- TAB 2: LOCAL DECRYPT ---
    def init_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        layout.addWidget(QLabel("Encrypted Archive Target (.enc / .zip.enc):"))
        target_h_layout = QHBoxLayout()
        self.dec_target_input = DropLineEdit()
        target_h_layout.addWidget(self.dec_target_input)

        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(lambda *args: self.browse_path(self.dec_target_input, "file"))
        target_h_layout.addWidget(btn_browse)
        layout.addLayout(target_h_layout)

        layout.addWidget(QLabel("Custom Destination (Optional):"))
        out_h_layout = QHBoxLayout()
        self.dec_output_input = DropLineEdit()
        self.dec_output_input.setPlaceholderText("Auto-generates next to target if left blank...")
        out_h_layout.addWidget(self.dec_output_input)

        btn_out_browse = QPushButton("Save As")
        btn_out_browse.clicked.connect(lambda *args: self.browse_save_path(self.dec_output_input))
        out_h_layout.addWidget(btn_out_browse)
        layout.addLayout(out_h_layout)

        layout.addWidget(QLabel("Master Password Verification:"))
        dec_pwd_row, self.dec_pass_input = self._create_password_field()
        layout.addLayout(dec_pwd_row)

        layout.addStretch()

        self.btn_unlock = QPushButton("LOCAL UNLOCK")
        self.btn_unlock.setFixedHeight(45)
        self.btn_unlock.setStyleSheet("QPushButton { background-color: #16a34a; } QPushButton:hover { background-color: #15803d; }")
        self.btn_unlock.clicked.connect(self.start_decryption_thread)
        layout.addWidget(self.btn_unlock)

        self.tabs.addTab(tab, "Local Decrypt")

    # --- TAB 3: ASYMMETRIC (RSA) ---
    def init_rsa_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(8)

        # 1. Key Generation Section
        lbl_keygen = QLabel("1. Identity Management")
        lbl_keygen.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_keygen)

        self.btn_keygen = QPushButton("Generate New RSA-4096 Keypair")
        self.btn_keygen.setStyleSheet("QPushButton { background-color: #6366f1; } QPushButton:hover { background-color: #4f46e5; }")
        self.btn_keygen.clicked.connect(self.start_rsa_keygen_thread)
        layout.addWidget(self.btn_keygen)

        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line1)

        # 2. Encrypt for Sharing
        lbl_share = QLabel("2. Package for Sharing (Requires Recipient's Public Key)")
        lbl_share.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_share)

        layout.addWidget(QLabel("Target File or Folder:"))
        h_rsa_enc_target = QHBoxLayout()
        self.rsa_enc_target = DropLineEdit()
        h_rsa_enc_target.addWidget(self.rsa_enc_target)
        btn_rsa_enc_file = QPushButton("File")
        btn_rsa_enc_file.clicked.connect(lambda *args: self.browse_path(self.rsa_enc_target, "file"))
        btn_rsa_enc_dir = QPushButton("Folder")
        btn_rsa_enc_dir.clicked.connect(lambda *args: self.browse_path(self.rsa_enc_target, "folder"))
        h_rsa_enc_target.addWidget(btn_rsa_enc_file)
        h_rsa_enc_target.addWidget(btn_rsa_enc_dir)
        layout.addLayout(h_rsa_enc_target)

        layout.addWidget(QLabel("Recipient's Public Key (.pem):"))
        h_rsa_pub = QHBoxLayout()
        self.rsa_pub_key = DropLineEdit()
        self.rsa_pub_key.textChanged.connect(self._update_pub_fingerprint)
        h_rsa_pub.addWidget(self.rsa_pub_key)
        btn_rsa_pub_browse = QPushButton("Browse")
        btn_rsa_pub_browse.clicked.connect(lambda *args: self.browse_path(self.rsa_pub_key, "file", filter="PEM Files (*.pem)"))
        h_rsa_pub.addWidget(btn_rsa_pub_browse)
        layout.addLayout(h_rsa_pub)

        self.rsa_pub_fp_label = QLabel("SHA-256 Fingerprint: (none selected)")
        self.rsa_pub_fp_label.setFont(QFont("Consolas", 8))
        self.rsa_pub_fp_label.setWordWrap(True)
        layout.addWidget(self.rsa_pub_fp_label)

        self.btn_rsa_enc = QPushButton("SECURE PACKAGE")
        self.btn_rsa_enc.clicked.connect(self.start_rsa_encrypt_thread)
        layout.addWidget(self.btn_rsa_enc)

        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line2)

        # 3. Decrypt Received File
        lbl_receive = QLabel("3. Unlock Received Package (Requires Your Private Key)")
        lbl_receive.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_receive)

        layout.addWidget(QLabel("Encrypted Package (.rsa.enc / .zip.rsa.enc):"))
        h_rsa_dec_target = QHBoxLayout()
        self.rsa_dec_target = DropLineEdit()
        h_rsa_dec_target.addWidget(self.rsa_dec_target)
        btn_rsa_dec_browse = QPushButton("Browse")
        btn_rsa_dec_browse.clicked.connect(lambda *args: self.browse_path(self.rsa_dec_target, "file"))
        h_rsa_dec_target.addWidget(btn_rsa_dec_browse)
        layout.addLayout(h_rsa_dec_target)

        layout.addWidget(QLabel("Your Private Key (.pem):"))
        h_rsa_priv = QHBoxLayout()
        self.rsa_priv_key = DropLineEdit()
        h_rsa_priv.addWidget(self.rsa_priv_key)
        btn_rsa_priv_browse = QPushButton("Browse")
        btn_rsa_priv_browse.clicked.connect(lambda *args: self.browse_path(self.rsa_priv_key, "file", filter="PEM Files (*.pem)"))
        h_rsa_priv.addWidget(btn_rsa_priv_browse)
        layout.addLayout(h_rsa_priv)

        self.btn_rsa_dec = QPushButton("UNLOCK PACKAGE")
        self.btn_rsa_dec.setStyleSheet("QPushButton { background-color: #16a34a; } QPushButton:hover { background-color: #15803d; }")
        self.btn_rsa_dec.clicked.connect(self.start_rsa_decrypt_thread)
        layout.addWidget(self.btn_rsa_dec)

        layout.addStretch()
        self.tabs.addTab(tab, "Asymmetric Sharing")

    # --- UI UTILITIES ---
    def _update_password_strength(self, password: str):
        score, label, advice = self.encryptor.evaluate_password_strength(password)
        self.strength_bar.setValue(score)
        if score < 30:
            color = "#ef4444"
        elif score < 50:
            color = "#f59e0b"
        elif score < 75:
            color = "#3b82f6"
        else:
            color = "#22c55e"
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; border-radius: 4px; }}")
        self.strength_label.setText(f"Strength: {label} - {advice}")

    def _update_pub_fingerprint(self, key_path: str):
        key_path = key_path.strip()
        if not key_path or not os.path.isfile(key_path):
            self.rsa_pub_fp_label.setText("SHA-256 Fingerprint: (none selected)")
            return
        try:
            fp = self.encryptor.get_public_key_fingerprint(key_path)
            self.rsa_pub_fp_label.setText(f"SHA-256 Fingerprint: {fp}")
        except Exception:
            self.rsa_pub_fp_label.setText("SHA-256 Fingerprint: (invalid PEM public key)")

    def browse_save_path(self, line_edit, filter=""):
        options = QFileDialog.Option.DontUseNativeDialog
        path, _ = QFileDialog.getSaveFileName(self, "Select Destination Path", filter=filter, options=options)
        if path:
            line_edit.setText(os.path.normpath(path))

    def browse_path(self, line_edit, mode, filter=""):
        options = QFileDialog.Option.DontUseNativeDialog
        if mode == "file":
            path, _ = QFileDialog.getOpenFileName(self, "Select File", filter=filter, options=options)
        else:
            path = QFileDialog.getExistingDirectory(self, "Select Directory", options=options)

        if path:
            line_edit.setText(os.path.normpath(path))

    def log(self, text):
        timestamp = datetime.now().strftime("%H:%M:%S")
        safe_text = html.escape(text)

        if "[CRITICAL]" in safe_text:
            formatted_text = f'<span style="color: #ef4444; font-weight: bold;">[{timestamp}] &gt; {safe_text}</span>'
        elif "[-]" in safe_text or "Error" in safe_text or "Aborted" in safe_text or "Failed" in safe_text:
            formatted_text = f'<span style="color: #ef4444;">[{timestamp}] &gt; {safe_text}</span>'
        elif "[!]" in safe_text or "Warning" in safe_text or "Check" in safe_text:
            formatted_text = f'<span style="color: #f59e0b;">[{timestamp}] &gt; {safe_text}</span>'
        elif "[+]" in safe_text:
            formatted_text = f'<span style="color: #3b82f6;">[{timestamp}] &gt; {safe_text}</span>'
        else:
            formatted_text = f"[{timestamp}] &gt; {safe_text}"

        self.console.append(formatted_text)

    def toggle_ui(self, enable):
        self.btn_lock.setEnabled(enable)
        self.btn_unlock.setEnabled(enable)
        self.btn_keygen.setEnabled(enable)
        self.btn_rsa_enc.setEnabled(enable)
        self.btn_rsa_dec.setEnabled(enable)
        self.btn_cancel.setEnabled(not enable)
        if enable:
            self.cancel_event.clear()
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Idle (%p%)")

    def update_progress(self, done: int, total: int):
        if total <= 0:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Processing... (100%)")
            return
        pct = min(100, int((done / total) * 100))
        done_mb = done / (1024 * 1024)
        total_mb = total / (1024 * 1024)
        self.progress_bar.setValue(pct)
        self.progress_bar.setFormat(f"{pct}% ({done_mb:.2f} / {total_mb:.2f} MB)")

    def request_cancel(self):
        if not self.cancel_event.is_set():
            self.cancel_event.set()
            self.btn_cancel.setEnabled(False)
            self.log("[*] Cancellation requested. Aborting safely at next block...")

    def _emit_progress(self, done: int, total: int):
        self.signals.progress_signal.emit(done, total)

    def clear_inputs(self, engine):
        if engine == "enc":
            self.enc_target_input.clear()
            self.enc_output_input.clear()
            self.enc_pass_input.clear()
            self.enc_conf_input.clear()
            self.shred_checkbox.setChecked(False)
        elif engine == "dec":
            self.dec_target_input.clear()
            self.dec_output_input.clear()
            self.dec_pass_input.clear()
        elif engine == "rsa_enc":
            self.rsa_enc_target.clear()
            self.rsa_pub_key.clear()
        elif engine == "rsa_dec":
            self.rsa_dec_target.clear()
            self.rsa_priv_key.clear()

    def _load_failed_attempts(self) -> dict:
        try:
            if os.path.isfile(self._attempts_file):
                with open(self._attempts_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {str(k): int(v) for k, v in data.items()}
        except Exception:
            pass
        return {}

    def _save_failed_attempts(self):
        try:
            with open(self._attempts_file, "w", encoding="utf-8") as f:
                json.dump(self.failed_attempts, f)
        except Exception:
            pass

    @staticmethod
    def _attempt_key(target: str) -> str:
        norm_path = os.path.normcase(os.path.abspath(target))
        try:
            with open(target, "rb") as f:
                header = f.read(28)
            if len(header) == 28:
                return f"hdr:{hashlib.sha256(header).hexdigest()}"
        except OSError:
            pass
        return f"path:{norm_path}"

    def prompt_overwrite_sync(self, path, container_list, done_event):
        try:
            reply = QMessageBox.question(
                self, 'Overwrite System Check',
                f"The target item '{os.path.basename(path)}' already exists.\n\nOverwrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
            )
            container_list.append(reply == QMessageBox.StandardButton.Yes)
        finally:
            done_event.set()

    def prompt_passphrase_sync(self, title, container_list, done_event):
        try:
            pwd, ok = QInputDialog.getText(
                self,
                title,
                "Enter passphrase for the encrypted private key:",
                QLineEdit.EchoMode.Password,
            )
            container_list.append(pwd if ok else None)
        finally:
            done_event.set()

    def _thread_safe_overwrite_check(self, out_path: str) -> bool:
        result_container = []
        done_event = threading.Event()
        self.signals.overwrite_request.emit(out_path, result_container, done_event)
        done_event.wait()
        return bool(result_container and result_container[0])

    def _thread_safe_passphrase_prompt(self, title: str):
        result_container = []
        done_event = threading.Event()
        self.signals.passphrase_request.emit(title, result_container, done_event)
        done_event.wait()
        return result_container[0] if result_container else None

    # --- TAB 1 THREADS (LOCAL ENCRYPT) ---
    def start_encryption_thread(self):
        target = self.enc_target_input.text().strip()
        custom_out = self.enc_output_input.text().strip() or None
        pwd = self.enc_pass_input.text()
        conf = self.enc_conf_input.text()
        shred = self.shred_checkbox.isChecked()

        if not target or not pwd:
            self.log("[-] Error: Missing target configuration paths or access tokens.")
            return
        if pwd != conf:
            self.log("[-] Error: Key verification validation mismatch.")
            return
        if not os.path.exists(target):
            self.log("[-] Error: Network/Local target path resolution failure.")
            return

        target_norm = os.path.normpath(target)
        expected_out = custom_out if custom_out else (f"{target_norm}.zip.enc" if os.path.isdir(target_norm) else f"{target_norm}.enc")
        if os.path.exists(expected_out):
            reply = QMessageBox.question(
                self, 'Overwrite Check', f"Archive '{os.path.basename(expected_out)}' already exists.\n\nOverwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                self.log("[-] Aborted to protect existing archive.")
                return

        self.cancel_event.clear()
        self.toggle_ui(False)
        threading.Thread(target=self._exec_encryption, args=(target_norm, pwd, shred, custom_out), daemon=True).start()

    def _exec_encryption(self, target, pwd, shred, custom_out):
        try:
            self.signals.log_signal.emit(f"Initializing encryption matrix for: {os.path.basename(target)}")
            if os.path.isdir(target):
                out = self.encryptor.encrypt_directory(
                    target, pwd, output_path=custom_out,
                    progress_callback=self._emit_progress, cancel_event=self.cancel_event,
                )
            else:
                out = self.encryptor.encrypt_file(
                    target, pwd, output_path=custom_out,
                    progress_callback=self._emit_progress, cancel_event=self.cancel_event,
                )

            self.signals.log_signal.emit(f"[+] Output locked to disk: {os.path.basename(out)}")

            if shred:
                self.signals.log_signal.emit("[*] Commencing anti-forensic wipe...")
                self.encryptor.secure_delete(target, progress_callback=self._emit_progress, cancel_event=self.cancel_event)
                self.signals.log_signal.emit("[+] Original data blocks completely wiped.")

            self.signals.clear_inputs_signal.emit("enc")
        except InterruptedError as ie:
            self.signals.log_signal.emit(f"[-] Operation Aborted: {str(ie)}")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Execution Aborted: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    # --- TAB 2 THREADS (LOCAL DECRYPT) ---
    def start_decryption_thread(self):
        target = self.dec_target_input.text().strip()
        custom_out = self.dec_output_input.text().strip() or None
        pwd = self.dec_pass_input.text()

        if not target or not pwd:
            self.log("[-] Error: Target payload and verification tokens required.")
            return
        if not os.path.isfile(target):
            self.log("[-] Error: Target file does not exist or is not a valid file.")
            return

        self.cancel_event.clear()
        self.toggle_ui(False)
        threading.Thread(target=self._exec_decryption, args=(target, pwd, custom_out), daemon=True).start()

    def _exec_decryption(self, target, pwd, custom_out):
        attempt_key = self._attempt_key(target)
        try:
            self.signals.log_signal.emit(f"Passing crypt-stream parameters for: {os.path.basename(target)}")

            if target.endswith('.zip.enc'):
                out = self.encryptor.decrypt_directory(
                    target, pwd, output_path=custom_out,
                    overwrite_callback=self._thread_safe_overwrite_check,
                    progress_callback=self._emit_progress, cancel_event=self.cancel_event,
                )
            else:
                out = self.encryptor.decrypt_file(
                    target, pwd, output_path=custom_out,
                    overwrite_callback=self._thread_safe_overwrite_check,
                    progress_callback=self._emit_progress, cancel_event=self.cancel_event,
                )

            self.signals.log_signal.emit(f"[+] Decrypted sequence output success: {os.path.basename(out)}")

            with self._attempts_lock:
                if attempt_key in self.failed_attempts:
                    del self.failed_attempts[attempt_key]
                    self._save_failed_attempts()

            self.signals.clear_inputs_signal.emit("dec")

        except InterruptedError as ie:
            self.signals.log_signal.emit(f"[-] Operation Aborted: {str(ie)}")
        except ValueError as ve:
            if "signature verification failed" in str(ve).lower():
                with self._attempts_lock:
                    attempts = self.failed_attempts.get(attempt_key, 0) + 1
                    self.failed_attempts[attempt_key] = attempts
                    self._save_failed_attempts()

                remaining = 5 - attempts
                if remaining > 0:
                    self.signals.log_signal.emit(f"[-] Incorrect Password. {remaining} attempts remaining before self-destruct.")
                else:
                    self.signals.log_signal.emit(f"[CRITICAL] 5 consecutive failed attempts. Triggering Dead Man's Switch...")
                    try:
                        self.encryptor.secure_delete(target)
                        self.signals.log_signal.emit(f"[!] Target '{os.path.basename(target)}' securely shredded from disk.")
                    except Exception as e:
                        self.signals.log_signal.emit(f"[-] Shredder execution failed: {e}")
                    with self._attempts_lock:
                        self.failed_attempts.pop(attempt_key, None)
                        self._save_failed_attempts()
            else:
                self.signals.log_signal.emit(f"[-] Authentication Failure: {ve}")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Critical Error: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    # --- TAB 3 THREADS (ASYMMETRIC RSA) ---
    def start_rsa_keygen_thread(self):
        options = QFileDialog.Option.DontUseNativeDialog
        save_dir = QFileDialog.getExistingDirectory(self, "Select Folder to Save Keys", options=options)
        if not save_dir:
            return

        priv_path = os.path.join(save_dir, "my_private_key.pem")
        pub_path = os.path.join(save_dir, "my_public_key.pem")
        if os.path.exists(priv_path) or os.path.exists(pub_path):
            reply = QMessageBox.question(
                self, 'Overwrite Existing Keys',
                "An existing RSA keypair was found in this folder.\n\n"
                "Overwriting your private key will permanently prevent decryption of older files.\n\nOverwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                self.log("[-] Key generation aborted to preserve existing keys.")
                return

        passphrase, ok = QInputDialog.getText(
            self,
            "Protect Private Key (Optional)",
            "Enter a passphrase to encrypt your private key (leave blank for none):",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            self.log("[-] Key generation cancelled.")
            return

        self.cancel_event.clear()
        self.toggle_ui(False)
        threading.Thread(target=self._exec_rsa_keygen, args=(save_dir, passphrase or None), daemon=True).start()

    def _exec_rsa_keygen(self, save_dir, passphrase):
        try:
            self.signals.log_signal.emit("[*] Generating 4096-bit RSA Keypair... (This may take a moment)")
            priv_path = os.path.join(save_dir, "my_private_key.pem")
            pub_path = os.path.join(save_dir, "my_public_key.pem")

            self.encryptor.generate_rsa_keypair(priv_path, pub_path, password=passphrase)
            fp = self.encryptor.get_public_key_fingerprint(pub_path)

            self.signals.log_signal.emit(f"[+] Success! Keys saved to: {save_dir}")
            self.signals.log_signal.emit(f"[+] Public Key SHA-256: {fp}")
            if passphrase:
                self.signals.log_signal.emit("[+] Private key is passphrase-protected (PKCS#8).")
            self.signals.log_signal.emit("[!] WARNING: Never share your PRIVATE key with anyone.")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Keygen Failed: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    def start_rsa_encrypt_thread(self):
        target = self.rsa_enc_target.text().strip()
        pub_key = self.rsa_pub_key.text().strip()

        if not target or not pub_key:
            self.log("[-] Error: Missing Target File/Folder or Recipient's Public Key.")
            return
        if not os.path.exists(target):
            self.log("[-] Error: Target path does not exist.")
            return
        if not os.path.isfile(pub_key):
            self.log("[-] Error: Recipient's Public Key file does not exist.")
            return

        target_norm = os.path.normpath(target)
        expected_out = f"{target_norm}.zip.rsa.enc" if os.path.isdir(target_norm) else f"{target_norm}.rsa.enc"
        if os.path.exists(expected_out):
            reply = QMessageBox.question(
                self, 'Overwrite Check', f"Package '{os.path.basename(expected_out)}' already exists.\n\nOverwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                self.log("[-] Aborted to protect existing RSA package.")
                return

        self.cancel_event.clear()
        self.toggle_ui(False)
        threading.Thread(target=self._exec_rsa_encrypt, args=(target_norm, pub_key), daemon=True).start()

    def _exec_rsa_encrypt(self, target, pub_key):
        try:
            self.signals.log_signal.emit(f"[*] Packaging payload via Hybrid RSA envelope: {os.path.basename(target)}")
            if os.path.isdir(target):
                out = self.encryptor.rsa_encrypt_directory(
                    target, pub_key,
                    progress_callback=self._emit_progress, cancel_event=self.cancel_event,
                )
            else:
                out = self.encryptor.rsa_encrypt_file(
                    target, pub_key,
                    progress_callback=self._emit_progress, cancel_event=self.cancel_event,
                )
            self.signals.log_signal.emit(f"[+] Secure package generated: {os.path.basename(out)}")
            self.signals.clear_inputs_signal.emit("rsa_enc")
        except InterruptedError as ie:
            self.signals.log_signal.emit(f"[-] Operation Aborted: {str(ie)}")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Packaging Failed: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    def start_rsa_decrypt_thread(self):
        target = self.rsa_dec_target.text().strip()
        priv_key = self.rsa_priv_key.text().strip()

        if not target or not priv_key:
            self.log("[-] Error: Missing Encrypted Package or your Private Key.")
            return
        if not os.path.isfile(target):
            self.log("[-] Error: Encrypted package file does not exist.")
            return
        if not os.path.isfile(priv_key):
            self.log("[-] Error: Private Key file does not exist.")
            return

        self.cancel_event.clear()
        self.toggle_ui(False)
        threading.Thread(target=self._exec_rsa_decrypt, args=(target, priv_key), daemon=True).start()

    def _exec_rsa_decrypt(self, target, priv_key):
        try:
            key_pwd = None
            if self.encryptor.is_private_key_encrypted(priv_key):
                key_pwd = self._thread_safe_passphrase_prompt("Private Key Passphrase")
                if key_pwd is None:
                    raise InterruptedError("Operation aborted (private key passphrase not provided).")

            self.signals.log_signal.emit(f"[*] Unlocking envelope with your Private Key: {os.path.basename(target)}")
            if target.endswith(".zip.rsa.enc"):
                out = self.encryptor.rsa_decrypt_directory(
                    target, priv_key,
                    overwrite_callback=self._thread_safe_overwrite_check,
                    key_password=key_pwd,
                    progress_callback=self._emit_progress,
                    cancel_event=self.cancel_event,
                )
            else:
                out = self.encryptor.rsa_decrypt_file(
                    target, priv_key,
                    overwrite_callback=self._thread_safe_overwrite_check,
                    key_password=key_pwd,
                    progress_callback=self._emit_progress,
                    cancel_event=self.cancel_event,
                )
            self.signals.log_signal.emit(f"[+] Package successfully unlocked: {os.path.basename(out)}")
            self.signals.clear_inputs_signal.emit("rsa_dec")
        except InterruptedError as ie:
            self.signals.log_signal.emit(f"[-] Operation Aborted: {str(ie)}")
        except ValueError as ve:
            self.signals.log_signal.emit(f"[-] Access Denied: {ve}")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Decryption Failed: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureVaultPyQt()
    window.show()
    sys.exit(app.exec())
