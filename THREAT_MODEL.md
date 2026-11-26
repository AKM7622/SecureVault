# SecureVault Threat Model

This document defines the security boundaries, protected assets, adversary capabilities, implemented mitigations, and explicit residual risks of **SecureVault (Enterprise PKI Edition)**.

---

## 1. Security Objectives & Assets

| Asset | Security Goal | Mechanism |
| :--- | :--- | :--- |
| **Local Files & Directories** | Confidentiality & Integrity at rest | `AES-256-GCM` with per-file 12-byte random nonce and 16-byte authentication tag; folders archived into temporary `.zip` files before encryption. |
| **Master Password** | Resistance to offline dictionary/brute-force attacks; zero plaintext storage | Never stored on disk; stretched via `PBKDF2-HMAC-SHA256` (480,000 iterations, 16-byte `os.urandom` salt). |
| **Shared Payloads (`.rsa.enc` / `.zip.rsa.enc`)** | Confidentiality in transit over untrusted channels | Ephemeral 256-bit AES-GCM content key wrapped with recipient's **RSA-4096** public key using `OAEP (MGF1-SHA256, SHA-256)`. |
| **RSA Private Key (`.pem`)** | Confidentiality if device/backup is accessed | PKCS#8 PEM format with optional `BestAvailableEncryption` passphrase protection. |
| **Deleted Plaintext Originals** | Anti-forensic resistance against file-carving recovery | Multi-pass in-place `"r+b"` chunked `os.urandom` overwrite + `flush()` + `os.fsync()` prior to `os.remove()`. |

---

## 2. Trust Boundaries

```text
+-------------------------------------------------------------------+
| Trusted Host OS & Local User Session (GUI / CLI + Python Process) |
|                                                                   |
|  [Plaintext File/Dir] ---> [FileEncryptor (AES-256-GCM / RSA)]    |
|         |                             |                           |
|   (Optional Shred)            (Encrypted Payload)                 |
+---------|-----------------------------|---------------------------+
          v                             v
   [Local Disk / SSD]         [Untrusted Storage / Network Transit]
```

- **Inside Trust Boundary**: The running Python process, OS memory during active encryption/decryption, and the user's private key (protected by OS permissions and optional passphrase).
- **Outside Trust Boundary**: Cloud drives, USB media, email/network transit, and offline disk snapshots containing `.enc` or `.rsa.enc` files.

---

## 3. Threats & Implemented Mitigations

| Threat | Mitigation in SecureVault |
| :--- | :--- |
| **Passive Eavesdropping / Cloud Storage Breach** | All file contents and directory names/structures (via `.zip` wrapping) are encrypted with AES-256-GCM. |
| **Ciphertext Tampering / Bit-Flipping Attacks** | AES-GCM 16-byte authentication tag verification fails (`InvalidTag`) before temporary output is committed via `os.replace()`. |
| **Malformed / Adversarial RSA Headers (DoS)** | `rsa_decrypt_file` validates minimum file size (`>= 33` bytes) and verifies the 4-byte `enc_key_len` matches `private_key.key_size // 8` and fits within `file_size` before reading. |
| **Zip Slip / Path Traversal in Directory Archives** | `_safe_extract_zip` canonicalizes every archive member path and rejects any entry escaping the extraction root. |
| **Plaintext Temp File Leakage** | Directory compression/decompression occurs inside `tempfile.TemporaryDirectory()`, temporary `.zip` archives are shredded in `finally:`, and failed `.tmp` outputs are deleted on error/cancellation. |
| **Public Key Substitution (MITM)** | SHA-256 public key fingerprints are computed and displayed in both CLI (`fingerprint` / `rsa-encrypt`) and GUI so users can verify keys out-of-band. |
| **Casual Local Guessing Attacks** | Dead Man's Switch tracks failed decryption attempts per file header fingerprint (`SHA-256(salt + nonce)`) in `~/.securevault_attempts.json` and shreds the vault after 5 consecutive failures. |
| **Accidental Key or File Overwrites** | Explicit overwrite checks guard decryption targets, RSA packages, and RSA keypair generation (`my_private_key.pem` / `my_public_key.pem`). |

---

## 4. Explicit Out-of-Scope Threats & Residual Risks

Responsible security engineering requires stating what the tool **cannot** protect against:

1. **SSD Wear-Leveling, TRIM & Copy-on-Write (CoW) Filesystems**: On modern SSDs, NVMe drives, or CoW filesystems (e.g., Btrfs/ZFS/APFS) and NTFS small resident files, user-space overwriting cannot guarantee that every physical flash block containing prior plaintext has been erased. Full-disk encryption (e.g., BitLocker/LUKS) is recommended alongside file shredding.
2. **Dead Man's Switch Bypass via File Copies or State Deletion**: A local adversary with disk read/write access can clone `.enc` files before guessing passwords or delete `~/.securevault_attempts.json`. The Dead Man's Switch deters casual/interactive guessing, not forensic offline cracking.
3. **Lack of Sender Authenticity in RSA-OAEP**: Because anyone with a recipient's public key can create a valid `.rsa.enc` package, RSA-OAEP provides confidentiality and ciphertext integrity, **not** sender identity verification (which would require sender digital signatures such as Ed25519 or RSA-PSS).
4. **Compromised Endpoint (Malware / Keyloggers / Memory Scraping)**: If the host OS is compromised while SecureVault is unlocked, an attacker can capture passwords, private keys, or decrypted files directly from memory or disk.
5. **Unchunked AEAD Temporary Disk Usage**: In the current v1 binary format, `decrypt_file` and `rsa_decrypt_file` verify the single trailing 16-byte GCM tag at stream end (`finalize()`), meaning unverified bytes touch a `.tmp` file briefly before being deleted on `InvalidTag`. (Planned for future v2 chunked AEAD format.)
