from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Protocol import KDF
import base64
import os
import struct
from Crypto.Hash import SHA256, HMAC


class BlowfishCipher(object):
    def __init__(self, key, salt):
        """
        Blowfish cipher, 256-bit key, 64-bit block

        :param key: Encryption key
        :param salt: Encryption salt
        """
        self.key = KDF.PBKDF2(password=key.encode(), salt=salt.encode(), dkLen=32, count=10000, prf=prf)

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext

        :param plaintext: Plaintext to encrypt
        :return: Encrypted message
        :rtype: str
        """
        plaintext = _pad(plaintext.encode(), AES.block_size)
        cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext

        :param ciphertext: Ciphertext to decrypt
        :return: Decrypted message
        :rtype: str
        """
        ciphertext = base64.b64decode(ciphertext)
        nonce = ciphertext[:16]
        tag = ciphertext[16:32]
        ciphertext = ciphertext[32:]
        cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
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

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher.nonce, tag, ciphertext)]

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

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 8, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX, nonce=nonce)

                    out_file.write(cipher.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)

def _pad(s, bs):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode()


def _unpad(s):
    return s[:-ord(s[len(s)-1:])]


def prf(p, s):
    return HMAC.new(p, s, SHA256).digest()


