import argparse
import getpass
import os
import sys
import threading

from crypto_backend import FileEncryptor


def _prompt_password(label: str = "Password: ", confirm: bool = False) -> str:
    pwd = getpass.getpass(label)
    if not pwd:
        raise ValueError("Password cannot be empty.")
    if confirm:
        conf = getpass.getpass("Confirm Password: ")
        if pwd != conf:
            raise ValueError("Passwords do not match.")
    return pwd


def _confirm_prompt(message: str) -> bool:
    if not sys.stdin.isatty():
        return False
    reply = input(f"{message} [y/N]: ").strip().lower()
    return reply in ("y", "yes")


def _make_progress_printer():
    last_pct = [-1]

    def _callback(done: int, total: int):
        if total <= 0:
            pct = 100
        else:
            pct = min(100, int((done / total) * 100))
        if pct != last_pct[0] and (pct % 5 == 0 or pct == 100):
            last_pct[0] = pct
            if sys.stdout.isatty():
                sys.stdout.write(f"\rProgress: {pct:3d}% ({done}/{total} bytes)")
                sys.stdout.flush()
                if pct == 100:
                    sys.stdout.write("\n")

    return _callback


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securevault",
        description="SecureVault Enterprise PKI CLI - AES-256-GCM & RSA-4096 file encryption utility.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Symmetric encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt a file or directory with AES-256-GCM.")
    p_enc.add_argument("target", help="Path to target file or directory.")
    p_enc.add_argument("-o", "--output", help="Custom output encrypted file path.")
    p_enc.add_argument("-p", "--password", help="Master password (omit to prompt securely).")
    p_enc.add_argument("--shred", action="store_true", help="Securely shred original target after encryption.")
    p_enc.add_argument("--passes", type=int, default=3, help="Overwrite passes when --shred is set (default: 3).")
    p_enc.add_argument("-f", "--force", action="store_true", help="Overwrite output file if it already exists.")

    # Symmetric decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt a .enc or .zip.enc archive.")
    p_dec.add_argument("target", help="Path to encrypted file.")
    p_dec.add_argument("-o", "--output", help="Custom output file or extraction folder.")
    p_dec.add_argument("-p", "--password", help="Master password (omit to prompt securely).")
    p_dec.add_argument("-f", "--force", action="store_true", help="Overwrite destination if it already exists.")

    # RSA keygen
    p_kg = sub.add_parser("keygen", help="Generate an RSA-4096 PEM keypair.")
    p_kg.add_argument("output_dir", help="Directory to save my_private_key.pem and my_public_key.pem.")
    p_kg.add_argument("--protect", action="store_true", help="Protect private key with a passphrase.")
    p_kg.add_argument("--key-password", help="Passphrase for private key (implies --protect).")
    p_kg.add_argument("-f", "--force", action="store_true", help="Overwrite existing key files if present.")

    # RSA encrypt
    p_renc = sub.add_parser("rsa-encrypt", help="Encrypt a file or folder using a recipient's RSA public key.")
    p_renc.add_argument("target", help="Path to target file or directory.")
    p_renc.add_argument("--pub", required=True, help="Recipient's RSA public key (.pem).")
    p_renc.add_argument("-o", "--output", help="Custom output package path.")
    p_renc.add_argument("--shred", action="store_true", help="Securely shred original target after encryption.")
    p_renc.add_argument("-f", "--force", action="store_true", help="Overwrite output package if it already exists.")

    # RSA decrypt
    p_rdec = sub.add_parser("rsa-decrypt", help="Decrypt an .rsa.enc or .zip.rsa.enc package with your private key.")
    p_rdec.add_argument("target", help="Path to encrypted RSA package.")
    p_rdec.add_argument("--priv", required=True, help="Your RSA private key (.pem).")
    p_rdec.add_argument("-o", "--output", help="Custom output file or extraction folder.")
    p_rdec.add_argument("--key-password", help="Passphrase for encrypted private key (prompts if needed).")
    p_rdec.add_argument("-f", "--force", action="store_true", help="Overwrite destination if it already exists.")

    # Public key fingerprint
    p_fp = sub.add_parser("fingerprint", help="Display the SHA-256 fingerprint of an RSA public key.")
    p_fp.add_argument("public_key", help="Path to PEM public key.")

    # Shred
    p_shred = sub.add_parser("shred", help="Securely overwrite and delete a file or directory.")
    p_shred.add_argument("target", help="Path to file or directory to shred.")
    p_shred.add_argument("--passes", type=int, default=3, help="Number of random overwrite passes (default: 3).")
    p_shred.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    encryptor = FileEncryptor()
    cancel_event = threading.Event()
    progress_cb = _make_progress_printer()

    try:
        if args.command == "encrypt":
            target = os.path.normpath(args.target)
            if not os.path.exists(target):
                raise FileNotFoundError(f"Target not found: {target}")
            expected_out = args.output or (f"{target}.zip.enc" if os.path.isdir(target) else f"{target}.enc")
            if os.path.exists(expected_out) and not args.force:
                if not _confirm_prompt(f"Output '{expected_out}' exists. Overwrite?"):
                    print("Aborted.")
                    return 2

            pwd = args.password or _prompt_password("Master Password: ", confirm=True)
            _, label, advice = encryptor.evaluate_password_strength(pwd)
            print(f"Password strength: {label} ({advice})")

            if os.path.isdir(target):
                out = encryptor.encrypt_directory(target, pwd, output_path=args.output, progress_callback=progress_cb, cancel_event=cancel_event)
            else:
                out = encryptor.encrypt_file(target, pwd, output_path=args.output, progress_callback=progress_cb, cancel_event=cancel_event)
            print(f"[+] Encrypted output: {out}")

            if args.shred:
                encryptor.secure_delete(target, passes=args.passes, cancel_event=cancel_event)
                print(f"[+] Original target shredded ({args.passes} passes): {target}")
            return 0

        if args.command == "decrypt":
            target = os.path.normpath(args.target)
            pwd = args.password or _prompt_password("Master Password: ")

            def overwrite_cb(path):
                return args.force or _confirm_prompt(f"Destination '{path}' exists. Overwrite?")

            if target.endswith(".zip.enc"):
                out = encryptor.decrypt_directory(
                    target, pwd, output_path=args.output, overwrite_callback=overwrite_cb,
                    progress_callback=progress_cb, cancel_event=cancel_event,
                )
            else:
                out = encryptor.decrypt_file(
                    target, pwd, output_path=args.output, overwrite_callback=overwrite_cb,
                    progress_callback=progress_cb, cancel_event=cancel_event,
                )
            print(f"[+] Decrypted output: {out}")
            return 0

        if args.command == "keygen":
            out_dir = os.path.normpath(args.output_dir)
            os.makedirs(out_dir, exist_ok=True)
            priv_path = os.path.join(out_dir, "my_private_key.pem")
            pub_path = os.path.join(out_dir, "my_public_key.pem")
            if (os.path.exists(priv_path) or os.path.exists(pub_path)) and not args.force:
                if not _confirm_prompt("Existing keypair detected in directory. Overwrite?"):
                    print("Aborted.")
                    return 2

            key_pwd = args.key_password
            if args.protect and not key_pwd:
                key_pwd = _prompt_password("Private Key Passphrase: ", confirm=True)

            print("[*] Generating 4096-bit RSA keypair...")
            encryptor.generate_rsa_keypair(priv_path, pub_path, password=key_pwd)
            fp = encryptor.get_public_key_fingerprint(pub_path)
            print(f"[+] Private key: {priv_path}")
            print(f"[+] Public key:  {pub_path}")
            print(f"[+] SHA-256 Fingerprint: {fp}")
            return 0

        if args.command == "rsa-encrypt":
            target = os.path.normpath(args.target)
            if not os.path.exists(target):
                raise FileNotFoundError(f"Target not found: {target}")
            expected_out = args.output or (f"{target}.zip.rsa.enc" if os.path.isdir(target) else f"{target}.rsa.enc")
            if os.path.exists(expected_out) and not args.force:
                if not _confirm_prompt(f"Package '{expected_out}' exists. Overwrite?"):
                    print("Aborted.")
                    return 2

            fp = encryptor.get_public_key_fingerprint(args.pub)
            print(f"[*] Recipient Public Key SHA-256: {fp}")
            if os.path.isdir(target):
                out = encryptor.rsa_encrypt_directory(
                    target, args.pub, output_path=args.output,
                    progress_callback=progress_cb, cancel_event=cancel_event,
                )
            else:
                out = encryptor.rsa_encrypt_file(
                    target, args.pub, output_path=args.output,
                    progress_callback=progress_cb, cancel_event=cancel_event,
                )
            print(f"[+] RSA package created: {out}")

            if args.shred:
                encryptor.secure_delete(target, cancel_event=cancel_event)
                print(f"[+] Original target shredded: {target}")
            return 0

        if args.command == "rsa-decrypt":
            target = os.path.normpath(args.target)
            key_pwd = args.key_password
            if key_pwd is None and encryptor.is_private_key_encrypted(args.priv):
                key_pwd = _prompt_password("Private Key Passphrase: ")

            def overwrite_cb(path):
                return args.force or _confirm_prompt(f"Destination '{path}' exists. Overwrite?")

            if target.endswith(".zip.rsa.enc"):
                out = encryptor.rsa_decrypt_directory(
                    target, args.priv, output_path=args.output, overwrite_callback=overwrite_cb,
                    key_password=key_pwd, progress_callback=progress_cb, cancel_event=cancel_event,
                )
            else:
                out = encryptor.rsa_decrypt_file(
                    target, args.priv, output_path=args.output, overwrite_callback=overwrite_cb,
                    key_password=key_pwd, progress_callback=progress_cb, cancel_event=cancel_event,
                )
            print(f"[+] Unlocked package: {out}")
            return 0

        if args.command == "fingerprint":
            fp = encryptor.get_public_key_fingerprint(args.public_key)
            print(f"SHA-256: {fp}")
            return 0

        if args.command == "shred":
            target = os.path.normpath(args.target)
            if not args.yes and not _confirm_prompt(f"Permanently shred '{target}' ({args.passes} passes)?"):
                print("Aborted.")
                return 2
            encryptor.secure_delete(target, passes=args.passes, progress_callback=progress_cb, cancel_event=cancel_event)
            print(f"[+] Securely shredded: {target}")
            return 0

    except KeyboardInterrupt:
        cancel_event.set()
        print("\n[-] Cancelled by user.", file=sys.stderr)
        return 2
    except InterruptedError as ie:
        print(f"\n[-] Aborted: {ie}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
