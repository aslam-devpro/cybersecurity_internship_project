# 🔐 Secure Storage Vault (with GUI)

A **secure file storage system** built in Python that allows you to:

* Encrypt sensitive files with a strong password
* Decrypt files when needed
* Verify file integrity
* View vault metadata
* Manage files easily via a **professional dark-themed GUI** (PyQt5)

---

## 🚀 Features

* AES-based file encryption & decryption
* Drag & drop file selection
* Password-protected vault initialization
* Metadata inspection (shows encrypted file details)
* Logs all actions with timestamps
* Works on **Windows, Linux, macOS**

---

## 📦 Installation

1. Clone or download this repository.
2. Install Python (>=3.8).
3. Install required libraries:

```bash
pip install PyQt5 cryptography
```

---

## ▶️ Running the App

Run the GUI:

```bash
python secure.py
```

This will open the **Secure Storage Vault** window.

---

## 🛠️ Usage Guide

### 1. **Select File**

* Drag & drop a file into the file input area, OR click the "Browse" button.

### 2. **Enter Password**

* Enter your vault password in the **Password field**.
* If the vault doesn’t exist, it will be initialized with this password.

### 3. **Encrypt**

* Click **Encrypt** to encrypt the selected file.
* The file will be stored in the vault.

### 4. **Decrypt**

* Select an encrypted file and click **Decrypt**.
* The decrypted file will be restored to the current working directory.

### 5. **Verify**

* Ensures that the encrypted file has not been tampered with.
* Displays success ✅ or warning ⚠️.

### 6. **View Metadata**

* Shows encrypted vault metadata (file hashes, timestamps, etc.) in a readable format.

### 6. **Tampered Data**

* Tamper with the encrypted file by erasing or replacing the content
* Try to decrypt this tampered file and you will encounter decryption error
* Hash verification also will fail since the file has been tampered with

---

## 🔒 Security Notes

* Always use a **strong password** for your vault.
* If you forget your password, files cannot be recovered.
* Metadata is encrypted, so unauthorized users can’t read vault info.
* Encrypted files can only be accessed with the correct password.

---

## 📜 License

This project is for **educational and personal use**.

---

Would you like me to:
👉 make this README as a **ready-to-download markdown file** (`README.md`) so you can directly add it to your repo?
