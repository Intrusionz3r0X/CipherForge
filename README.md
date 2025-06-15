# CipherForge

![Status](https://img.shields.io/badge/status-stable-green?style=flat-square)
![Python](https://img.shields.io/badge/python-3.x-blue?style=flat-square)

**CipherForge** is a lightweight payload obfuscation tool for red team operators and malware researchers. It supports **RC4**, **XOR**, and **AES (CBC)** encryption for raw shellcode and can optionally output the result in **C++ array format**—ideal for payload embedding in custom loaders or droppers.

> ⚠️ **Disclaimer:** This tool is intended for **educational, research, and authorized offensive security use only**. Do **not** use it on any system without **explicit permission**.

---

## 🎯 Use Case

CipherForge is useful for:

- Red team payload encryption before staging/delivery
- Malware development R&D (encryption & obfuscation techniques)
- AV/EDR evasion testing in lab environments
- Creating shellcode-ready C++ payloads
- Demonstrating how malware avoids static detection

---

## 🔐 Supported Encryption Modes

- 🔁 `RC4`: Stream cipher (pseudo-random key stream XOR)
- ✖️ `XOR`: Classic one-time pad–style XOR encryption
- 🔒 `AES`: AES-128 in CBC mode (with random IV, PKCS7 padding)

---

## 🛠️ Requirements

- Python 3.x
- `pyfiglet`
- `pycryptodome`

Install them using:

```bash
pip install pyfiglet pycryptodome
```
