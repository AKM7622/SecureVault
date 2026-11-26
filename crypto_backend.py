import os
import shutil
import stat
import tempfile
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


class FileEncryptor:
    def __init__(self):
        self.iterations = 480_000
        self.chunk_size = 64 * 1024

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def _make_temp_path(target_path: str) -> str:
        target_dir = os.path.dirname(os.path.abspath(target_path)) or "."
        os.makedirs(target_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".sv_tmp_", suffix=".tmp", dir=target_dir)
        os.close(fd)
        return tmp_path

    @staticmethod
    def _cleanup_file(path: str):
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    def encrypt_file(self, input_path: str, password: str, output_path: str = None) -> str:
        if not os.path.isfile(input_path):
            raise ValueError("Target path is not a valid file.")

        salt = os.urandom(16)
        nonce = os.urandom(12)

        key = self._derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        if not output_path:
            output_path = f"{input_path}.enc"

        tmp_output_path = self._make_temp_path(output_path)
        try:
            with open(input_path, 'rb') as f_in, open(tmp_output_path, 'wb') as f_out:
                f_out.write(salt + nonce)
                while chunk := f_in.read(self.chunk_size):
                    f_out.write(encryptor.update(chunk))
                encryptor.finalize()
                f_out.write(encryptor.tag)
            os.replace(tmp_output_path, output_path)
        except Exception:
            self._cleanup_file(tmp_output_path)
            raise

        return output_path

    def decrypt_file(self, input_path: str, password: str, output_path: str = None, overwrite_callback=None) -> str:
        if not os.path.isfile(input_path):
            raise ValueError("Target path is not a valid file.")

        file_size = os.path.getsize(input_path)
        if file_size < 44:
            raise ValueError("Target structure payload is too short or corrupted.")

        if not output_path:
            output_path = input_path[:-4] if input_path.endswith('.enc') else f"{input_path}.dec"

        tmp_output_path = self._make_temp_path(output_path)
        try:
            with open(input_path, 'rb') as f_in:
                salt = f_in.read(16)
                nonce = f_in.read(12)

                f_in.seek(file_size - 16)
                tag = f_in.read(16)

                ciphertext_len = file_size - 16 - 28
                key = self._derive_key(password, salt)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()

                f_in.seek(28)
                bytes_processed = 0

                with open(tmp_output_path, 'wb') as f_out:
                    while bytes_processed < ciphertext_len:
                        to_read = min(self.chunk_size, ciphertext_len - bytes_processed)
                        chunk = f_in.read(to_read)
                        if not chunk:
                            break
                        f_out.write(decryptor.update(chunk))
                        bytes_processed += len(chunk)

                    try:
                        f_out.write(decryptor.finalize())
                    except InvalidTag:
                        raise ValueError("Decryption signature verification failed. Bad token or payload tampered.")

            if os.path.exists(output_path) and overwrite_callback:
                if not overwrite_callback(output_path):
                    raise InterruptedError("Operation aborted to protect existing file.")

            os.replace(tmp_output_path, output_path)
        except Exception:
            self._cleanup_file(tmp_output_path)
            raise

        return output_path

    def encrypt_directory(self, dir_path: str, password: str, output_path: str = None) -> str:
        dir_path = os.path.normpath(dir_path)
        if not os.path.isdir(dir_path):
            raise ValueError("Target path resolution is not a valid directory.")

        if not output_path:
            output_path = f"{dir_path}.zip.enc"

        with tempfile.TemporaryDirectory(prefix="sv_zip_") as tmp_dir:
            archive_base = os.path.join(tmp_dir, "payload")
            archive_path = shutil.make_archive(base_name=archive_base, format='zip', root_dir=dir_path)
            try:
                return self.encrypt_file(archive_path, password, output_path)
            finally:
                if os.path.isfile(archive_path):
                    self._shred_file(archive_path, passes=1)

    @staticmethod
    def _safe_extract_zip(zip_path: str, extract_dir: str):
        abs_extract_dir = os.path.abspath(extract_dir)
        os.makedirs(abs_extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                member_path = os.path.abspath(os.path.join(abs_extract_dir, member.filename))
                if not (member_path == abs_extract_dir or member_path.startswith(abs_extract_dir + os.sep)):
                    raise ValueError(f"Unsafe archive member path detected: {member.filename}")
            zf.extractall(abs_extract_dir)

    def decrypt_directory(self, input_path: str, password: str, output_path: str = None, overwrite_callback=None) -> str:
        if not os.path.isfile(input_path):
            raise ValueError("Target path is not a valid file.")

        if output_path:
            extract_path = output_path
        elif input_path.endswith('.zip.enc'):
            extract_path = f"{input_path[:-8]}_decrypted"
        else:
            extract_path = f"{input_path}_decrypted"

        with tempfile.TemporaryDirectory(prefix="sv_unzip_") as tmp_dir:
            temp_zip_out = os.path.join(tmp_dir, "payload.zip")
            decrypted_zip_path = self.decrypt_file(input_path, password, output_path=temp_zip_out)

            if not zipfile.is_zipfile(decrypted_zip_path):
                raise ValueError("Target element structure does not validate as a directory archive.")

            if os.path.exists(extract_path) and overwrite_callback:
                if not overwrite_callback(extract_path):
                    raise InterruptedError("Operation aborted to protect existing folder.")

            self._safe_extract_zip(decrypted_zip_path, extract_path)

        return extract_path

    def secure_delete(self, path: str, passes: int = 3):
        if os.path.islink(path):
            os.unlink(path)
        elif os.path.isfile(path):
            self._shred_file(path, passes)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    file_entry = os.path.join(root, name)
                    if os.path.islink(file_entry):
                        os.unlink(file_entry)
                    else:
                        self._shred_file(file_entry, passes)
                for name in dirs:
                    dir_entry = os.path.join(root, name)
                    if os.path.islink(dir_entry):
                        os.unlink(dir_entry)
            shutil.rmtree(path)
        else:
            raise FileNotFoundError(f"Target does not exist: {path}")

    def _shred_file(self, file_path: str, passes: int):
        if passes < 1:
            raise ValueError("Shredding passes must be at least 1.")
        try:
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            length = os.path.getsize(file_path)
            if length > 0:
                with open(file_path, "r+b") as f:
                    for _ in range(passes):
                        f.seek(0)
                        remaining = length
                        while remaining > 0:
                            to_write = min(self.chunk_size, remaining)
                            f.write(os.urandom(to_write))
                            remaining -= to_write
                        f.flush()
                        os.fsync(f.fileno())
            os.remove(file_path)
        except Exception as e:
            raise Exception(f"Anti-forensics execution failed on {file_path}: {e}")

    def generate_rsa_keypair(self, private_out_path: str, public_out_path: str, password: str = None):
        """Generates a secure 4096-bit RSA keypair and saves them as PEM files."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        encryption_alg = (
            serialization.BestAvailableEncryption(password.encode('utf-8'))
            if password
            else serialization.NoEncryption()
        )

        tmp_priv = self._make_temp_path(private_out_path)
        tmp_pub = self._make_temp_path(public_out_path)
        try:
            with open(tmp_priv, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_alg,
                ))

            public_key = private_key.public_key()
            with open(tmp_pub, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ))

            os.replace(tmp_priv, private_out_path)
            os.replace(tmp_pub, public_out_path)
        except Exception:
            self._cleanup_file(tmp_priv)
            self._cleanup_file(tmp_pub)
            raise

    def rsa_encrypt_file(self, input_path: str, public_key_path: str, output_path: str = None) -> str:
        """Encrypts a file using a random AES key, then locks that AES key with a recipient's RSA Public Key."""
        if not os.path.isfile(input_path):
            raise ValueError("Target path is not a valid file.")
        if not os.path.isfile(public_key_path):
            raise ValueError("Public key path is not a valid file.")

        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Provided key is not a valid RSA public key.")

        aes_key = os.urandom(32)
        nonce = os.urandom(12)

        enc_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        if not output_path:
            output_path = f"{input_path}.rsa.enc"

        tmp_output_path = self._make_temp_path(output_path)
        try:
            with open(input_path, 'rb') as f_in, open(tmp_output_path, 'wb') as f_out:
                enc_key_len = len(enc_aes_key).to_bytes(4, byteorder='big')
                f_out.write(enc_key_len + enc_aes_key + nonce)

                while chunk := f_in.read(self.chunk_size):
                    f_out.write(encryptor.update(chunk))

                encryptor.finalize()
                f_out.write(encryptor.tag)
            os.replace(tmp_output_path, output_path)
        except Exception:
            self._cleanup_file(tmp_output_path)
            raise

        return output_path

    def rsa_decrypt_file(
        self,
        input_path: str,
        private_key_path: str,
        output_path: str = None,
        overwrite_callback=None,
        key_password: str = None,
    ) -> str:
        """Unlocks the RSA envelope using a Private Key, extracts the AES key, and decrypts the file stream."""
        if not os.path.isfile(input_path):
            raise ValueError("Target package path is not a valid file.")
        if not os.path.isfile(private_key_path):
            raise ValueError("Private key path is not a valid file.")

        file_size = os.path.getsize(input_path)
        if file_size < 33:
            raise ValueError("Target RSA package is too short or corrupted.")

        with open(private_key_path, "rb") as key_file:
            pwd_bytes = key_password.encode('utf-8') if key_password else None
            private_key = serialization.load_pem_private_key(key_file.read(), password=pwd_bytes)

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Provided key is not a valid RSA private key.")

        expected_rsa_bytes = private_key.key_size // 8

        if not output_path:
            if input_path.endswith('.rsa.enc'):
                output_path = f"{input_path[:-8]}.dec"
            else:
                output_path = f"{input_path}.dec"

        tmp_output_path = self._make_temp_path(output_path)
        try:
            with open(input_path, 'rb') as f_in:
                enc_key_len = int.from_bytes(f_in.read(4), byteorder='big')
                if enc_key_len <= 0 or enc_key_len != expected_rsa_bytes or (4 + enc_key_len + 12 + 16) > file_size:
                    raise ValueError("Invalid or corrupted RSA package header.")

                enc_aes_key = f_in.read(enc_key_len)
                nonce = f_in.read(12)

                try:
                    aes_key = private_key.decrypt(
                        enc_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        )
                    )
                except Exception:
                    raise ValueError("RSA Decryption Failed: The private key does not match this payload.")

                f_in.seek(file_size - 16)
                tag = f_in.read(16)

                ciphertext_len = file_size - 16 - 4 - enc_key_len - 12
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()

                f_in.seek(4 + enc_key_len + 12)
                bytes_processed = 0

                with open(tmp_output_path, 'wb') as f_out:
                    while bytes_processed < ciphertext_len:
                        to_read = min(self.chunk_size, ciphertext_len - bytes_processed)
                        chunk = f_in.read(to_read)
                        if not chunk:
                            break
                        f_out.write(decryptor.update(chunk))
                        bytes_processed += len(chunk)

                    try:
                        f_out.write(decryptor.finalize())
                    except InvalidTag:
                        raise ValueError("Integrity check failed. Payload tampered during transit.")

            if os.path.exists(output_path) and overwrite_callback:
                if not overwrite_callback(output_path):
                    raise InterruptedError("Operation aborted to protect existing file.")

            os.replace(tmp_output_path, output_path)
        except Exception:
            self._cleanup_file(tmp_output_path)
            raise

        return output_path