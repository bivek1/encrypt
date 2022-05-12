from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Protocol import KDF
from Crypto.Hash import SHA256, HMAC
import base64
import os
import struct


class RSAEncryption(object):
    def __init__(self, public_key_loc=None, private_key_loc=None,
                 public_key_passphrase=None, private_key_passphrase=None):
        """
        Hybrid AES-RSA cipher

        :param public_key_loc: Path to public key file
        :param private_key_loc: Path to private key file
        :param public_key_passphrase: Public key passphrase
        :param private_key_passphrase: Private key passphrase
        """
        self.public_key_loc = public_key_loc
        self.private_key_loc = private_key_loc
        self.public_key_passphrase = public_key_passphrase
        self.private_key_passphrase = private_key_passphrase

    def generate_keys(self, keys_size=2048):
        """
        Generate new RSA keys

        :param keys_size: Keys size
        """
        random_generator = Random.new().read
        keys = RSA.generate(keys_size, random_generator)

        with open(self.public_key_loc, 'wb') as public_key_file:
            public_key_file.write(keys.publickey().exportKey(format='PEM', passphrase=self.public_key_passphrase))

        with open(self.private_key_loc, 'wb') as private_key_file:
            private_key_file.write(keys.exportKey(format='PEM', passphrase=self.private_key_passphrase))

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext

        :param plaintext: Plaintext to encrypt
        :return: Encrypted message
        :rtype: str
        """
        plaintext = _pad(plaintext.encode(), AES.block_size)
        session_key = Random.get_random_bytes(32)

        with open(self.public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.public_key_passphrase))

        cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        return base64.b64encode(cipher_rsa.encrypt(session_key) + cipher_aes.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext

        :param ciphertext: Ciphertext to decrypt
        :return: Decrypted message
        :rtype: str
        """
        with open(self.private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        ciphertext = base64.b64decode(ciphertext)
        session_key = cipher_rsa.decrypt(ciphertext[:private_key.size_in_bytes()])
        nonce = ciphertext[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
        tag = ciphertext[private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 32]

        ciphertext = ciphertext[32 + private_key.size_in_bytes():]
        cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Encrypts the file

        :param in_file_name: Encrypting file name
        :param out_file_name: Encrypted file name (default is in_file_name + .enc)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)
        session_key = Random.get_random_bytes(32)

        with open(self.public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.public_key_passphrase))
        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))
                out_file.write(cipher_rsa.encrypt(session_key))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX)
                    ciphertext, tag = cipher_aes.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Decrypts the file

        :param in_file_name: Decrypting file name
        :param out_file_name: Decrypted file name (default in in_file_name without extension,
        if no extension - in_file_name + .decrypted)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(self.private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]
                session_key = cipher_rsa.decrypt(in_file.read(private_key.size_in_bytes()))

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 16, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX, nonce=nonce)

                    out_file.write(cipher_aes.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


def _pad(s, bs):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode()


def _unpad(s):
    return s[:-ord(s[len(s)-1:])]


def prf(p, s):
    return HMAC.new(p, s, SHA256).digest()

# public_key = "G:\Client Work\Assignment Project\WebApp\public_key.pem"
# private_key = "G:\Client Work\Assignment Project\WebApp\private_key.pem"

# obj = HybridAESRSACipher(public_key_loc=public_key, private_key_loc=private_key,
#                  public_key_passphrase="beb", private_key_passphrase="salt")

# file_path = "G:/Client Work/Assignment Project/WebApp\encrypt/media\encrypt/1.jpg"

# obj.encrypt_file(file_path)