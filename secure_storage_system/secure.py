#!/usr/bin/env python3
"""
Secure Vault GUI - Dark Theme, Professional
Integrates AES-256-GCM backend with PyQt5 frontend.
"""

import sys
import time
import json
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit,
    QFileDialog, QMessageBox, QGroupBox, QFormLayout, QFrame
)
from PyQt5.QtGui import QFont, QTextCursor, QIcon
from PyQt5.QtCore import Qt, QEvent

# --- Backend functions (paste your full backend here or import) ---
import secrets
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

KDF_ITERATIONS = 250_000
SALT_SIZE = 16
AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
METADATA_FILENAME = "metadata.json.enc"
SALT_FILENAME = "salt.bin"
ENCRYPTED_DIRNAME = "encrypted"

# --- Crypto & vault helpers ---
def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password)

def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(GCM_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def aesgcm_decrypt(key: bytes, blob: bytes, associated_data: bytes = None) -> bytes:
    if len(blob) < GCM_NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce = blob[:GCM_NONCE_SIZE]
    ct = blob[GCM_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def _vault_paths(vault_path: Path):
    return {
        "salt": vault_path / SALT_FILENAME,
        "metadata": vault_path / METADATA_FILENAME,
        "encrypted_dir": vault_path / ENCRYPTED_DIRNAME,
    }

def init_vault_if_missing(vault_path: Path, password: bytes):
    paths = _vault_paths(vault_path)
    vault_path.mkdir(parents=True, exist_ok=True)
    if not paths["salt"].exists():
        salt = secrets.token_bytes(SALT_SIZE)
        paths["salt"].write_bytes(salt)
        key = derive_key(password, salt)
        metadata = {"files": []}
        enc = aesgcm_encrypt(key, json.dumps(metadata).encode())
        paths["metadata"].write_bytes(enc)
        paths["encrypted_dir"].mkdir(exist_ok=True)
        return True
    return False

def load_metadata(vault_path: Path, key: bytes) -> dict:
    paths = _vault_paths(vault_path)
    if not paths["metadata"].exists():
        raise FileNotFoundError("Encrypted metadata not found; initialize the vault first.")
    enc = paths["metadata"].read_bytes()
    pt = aesgcm_decrypt(key, enc)
    return json.loads(pt.decode())

def save_metadata(vault_path: Path, key: bytes, metadata: dict):
    paths = _vault_paths(vault_path)
    enc = aesgcm_encrypt(key, json.dumps(metadata).encode())
    paths["metadata"].write_bytes(enc)

def encrypt_file(vault_path: Path, key: bytes, filepath: Path) -> str:
    plaintext = filepath.read_bytes()
    file_hash = sha256_bytes(plaintext)
    enc_blob = aesgcm_encrypt(key, plaintext)
    enc_name = filepath.name + ".enc"
    enc_path = vault_path / ENCRYPTED_DIRNAME / enc_name
    enc_path.write_bytes(enc_blob)
    metadata = load_metadata(vault_path, key)
    entry = {
        "enc_name": enc_name,
        "original_name": filepath.name,
        "timestamp": int(time.time()),
        "sha256": file_hash,
        "size_plain": len(plaintext),
        "size_enc": len(enc_blob),
    }
    metadata["files"].append(entry)
    save_metadata(vault_path, key, metadata)
    return enc_name

def decrypt_file(vault_path: Path, key: bytes, enc_filename: str, out_dir: Path = None, force=False) -> Path:
    enc_path = vault_path / ENCRYPTED_DIRNAME / enc_filename
    enc_blob = enc_path.read_bytes()
    plaintext = aesgcm_decrypt(key, enc_blob)
    metadata = load_metadata(vault_path, key)
    entry = next((e for e in metadata["files"] if e["enc_name"] == enc_filename), None)
    expected_hash = entry.get("sha256") if entry else None
    actual_hash = sha256_bytes(plaintext)
    if expected_hash and not constant_time.bytes_eq(actual_hash.encode(), expected_hash.encode()):
        raise ValueError("Hash mismatch: possible tampering or wrong key")
    out_dir = out_dir or Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / (entry["original_name"] if entry else enc_filename.replace('.enc', '.dec'))
    if out_path.exists() and not force:
        raise FileExistsError("Output exists; use force=True to overwrite")
    out_path.write_bytes(plaintext)
    return out_path

def verify_file(vault_path: Path, key: bytes, enc_filename: str) -> bool:
    enc_path = vault_path / ENCRYPTED_DIRNAME / enc_filename
    enc_blob = enc_path.read_bytes()
    try:
        plaintext = aesgcm_decrypt(key, enc_blob)
    except Exception:
        return False
    actual_hash = sha256_bytes(plaintext)
    metadata = load_metadata(vault_path, key)
    entry = next((e for e in metadata["files"] if e["enc_name"] == enc_filename), None)
    if not entry:
        return False
    return constant_time.bytes_eq(actual_hash.encode(), entry["sha256"].encode())

# --- GUI ---
class VaultGUIPro(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡 Secure Vault - AES-256-GCM")
        self.resize(850, 600)
        self.vault_path = Path('./myvault')
        self.selected_file = None
        self.setAcceptDrops(True)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Vault selector
        vault_box = QGroupBox("Vault Directory")
        vault_layout = QHBoxLayout()
        self.vault_label = QLabel(str(self.vault_path))
        self.vault_label.setFrameShape(QFrame.Panel)
        self.vault_label.setFrameShadow(QFrame.Sunken)
        btn_choose_vault = QPushButton("Browse...")
        btn_choose_vault.setIcon(QIcon.fromTheme("folder"))
        btn_choose_vault.clicked.connect(self.choose_vault)
        vault_layout.addWidget(QLabel("Vault:"))
        vault_layout.addWidget(self.vault_label)
        vault_layout.addWidget(btn_choose_vault)
        vault_box.setLayout(vault_layout)
        layout.addWidget(vault_box)

        # Password input
        form_box = QGroupBox("Authentication")
        form_layout = QFormLayout()
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Password:", self.pwd_input)
        form_box.setLayout(form_layout)
        layout.addWidget(form_box)

        # File selector
        file_box = QGroupBox("File Selection (Drag & Drop Supported)")
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.file_label.setFrameShape(QFrame.Panel)
        self.file_label.setFrameShadow(QFrame.Sunken)
        self.file_label.setMinimumWidth(400)
        self.file_label.setAlignment(Qt.AlignCenter)
        self.file_label.setStyleSheet("background-color:#2e2e2e; color:#ffffff;")
        btn_select_file = QPushButton("Select File")
        btn_select_file.setIcon(QIcon.fromTheme("document-open"))
        btn_select_file.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(btn_select_file)
        file_box.setLayout(file_layout)
        layout.addWidget(file_box)

        # Action buttons
        actions_box = QGroupBox("Actions")
        actions_layout = QHBoxLayout()
        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_encrypt.setIcon(QIcon.fromTheme("document-encrypt"))
        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.setIcon(QIcon.fromTheme("document-decrypt"))
        self.btn_verify = QPushButton("Verify")
        self.btn_verify.setIcon(QIcon.fromTheme("emblem-ok"))
        self.btn_metadata = QPushButton("Show Metadata")
        self.btn_metadata.setIcon(QIcon.fromTheme("dialog-information"))

        for btn in [self.btn_encrypt, self.btn_decrypt, self.btn_verify, self.btn_metadata]:
            btn.setFixedHeight(45)
            btn.setFont(QFont("Segoe UI", 10, QFont.Bold))

        self.btn_encrypt.clicked.connect(self.handle_encrypt)
        self.btn_decrypt.clicked.connect(self.handle_decrypt)
        self.btn_verify.clicked.connect(self.handle_verify)
        self.btn_metadata.clicked.connect(self.handle_metadata)

        actions_layout.addWidget(self.btn_encrypt)
        actions_layout.addWidget(self.btn_decrypt)
        actions_layout.addWidget(self.btn_verify)
        actions_layout.addWidget(self.btn_metadata)
        actions_box.setLayout(actions_layout)
        layout.addWidget(actions_box)

        # Log area
        log_box = QGroupBox("Vault Log")
        log_layout = QVBoxLayout()
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        self.log.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.log)
        log_box.setLayout(log_layout)
        layout.addWidget(log_box)

        self.setLayout(layout)

    # Drag & drop
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            self.selected_file = Path(urls[0].toLocalFile())
            self.file_label.setText(self.selected_file.name)
            self.log_msg(f"File dragged & dropped: {self.selected_file}", "info")

    # Logging
    def log_msg(self, msg: str, type="info"):
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        color = {"info":"#f1fa8c", "error":"#ff5555", "success":"#50fa7b"}.get(type,"#f1fa8c")
        self.log.append(f"<span style='color:{color}'>[{ts}] {msg}</span>")
        self.log.moveCursor(QTextCursor.End)

    # Vault/File selection
    def choose_vault(self):
        d = QFileDialog.getExistingDirectory(self, "Select Vault Directory", str(self.vault_path))
        if d:
            self.vault_path = Path(d)
            self.vault_label.setText(str(self.vault_path))
            self.log_msg(f"Vault set to: {self.vault_path}", "info")

    def select_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select File")
        if f:
            self.selected_file = Path(f)
            self.file_label.setText(self.selected_file.name)
            self.log_msg(f"Selected file: {self.selected_file}", "info")

    # --- Action methods ---
    def handle_encrypt(self):
        if not self.selected_file:
            self.log_msg("No file selected for encryption", "error")
            return
        pwd = self.pwd_input.text()
        if not pwd:
            self.log_msg("Password required", "error")
            return
        try:
            init_vault_if_missing(self.vault_path, pwd.encode())
            key = derive_key(pwd.encode(), (_vault_paths(self.vault_path)["salt"]).read_bytes())
            enc_name = encrypt_file(self.vault_path, key, self.selected_file)
            self.log_msg(f"Encrypted -> {enc_name}", "success")
            QMessageBox.information(self, "Encrypted", f"File encrypted as {enc_name}")
        except Exception as e:
            self.log_msg(f"Encryption error: {e}", "error")
            QMessageBox.critical(self, "Encrypt Failed", str(e))

    def handle_decrypt(self):
        if not self.selected_file:
            self.log_msg("No file selected for decryption", "error")
            return
        pwd = self.pwd_input.text()
        if not pwd:
            self.log_msg("Password required", "error")
            return
        try:
            key = derive_key(pwd.encode(), (_vault_paths(self.vault_path)["salt"]).read_bytes())
            out_path = decrypt_file(self.vault_path, key, self.selected_file.name, out_dir=Path.cwd(), force=False)
            self.log_msg(f"Decrypted -> {out_path}", "success")
            QMessageBox.information(self, "Decrypted", f"File decrypted to {out_path}")
        except Exception as e:
            self.log_msg(f"Decryption error: {e}", "error")
            QMessageBox.critical(self, "Decrypt Failed", str(e))

    def handle_verify(self):
        if not self.selected_file:
            self.log_msg("No file selected for verification", "error")
            return
        pwd = self.pwd_input.text()
        if not pwd:
            self.log_msg("Password required", "error")
            return
        try:
            key = derive_key(pwd.encode(), (_vault_paths(self.vault_path)["salt"]).read_bytes())
            result = verify_file(self.vault_path, key, self.selected_file.name)
            if result:
                self.log_msg(f"Verification successful: {self.selected_file.name}", "success")
                QMessageBox.information(self, "Verify", "File is authentic ✅")
            else:
                self.log_msg(f"Verification failed: {self.selected_file.name}", "error")
                QMessageBox.warning(self, "Verify", "Verification failed ⚠️")
        except Exception as e:
            self.log_msg(f"Verify error: {e}", "error")
            QMessageBox.critical(self, "Verify Error", str(e))

    def handle_metadata(self):
        pwd = self.pwd_input.text()
        if not pwd:
            self.log_msg("Password required", "error")
            return
        try:
            key = derive_key(pwd.encode(), (_vault_paths(self.vault_path)["salt"]).read_bytes())
            metadata = load_metadata(self.vault_path, key)
            pretty = json.dumps(metadata, indent=2)
            dlg = QMessageBox(self)
            dlg.setWindowTitle("Vault Metadata")
            dlg.setText("Encrypted Metadata:")
            dlg.setDetailedText(pretty)
            dlg.exec_()
            self.log_msg("Displayed metadata", "info")
        except Exception as e:
            self.log_msg(f"Metadata error: {e}", "error")
            QMessageBox.critical(self, "Metadata Error", str(e))

# --- Entry point ---
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = VaultGUIPro()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
