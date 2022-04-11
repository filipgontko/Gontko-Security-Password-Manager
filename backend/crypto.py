import hashlib
import secrets
import random
import string
import os

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16


def generate_crypto_key_base():
    """
    Generate and write into a file a crypto key base that will be used to encrypt and decrypt messages.
    """
    if not (key_exists()):
        key = generate_password(25)
        try:
            with open("secret.key", "w") as crypto_key_file:
                crypto_key_file.write(key)
        except IOError as e:
            return e


def key_exists():
    """
    Validate if a key exists
    :return: True if the key exists, False otherwise
    """
    return os.path.isfile('secret.key')


def load_crypto_key_base_from_file():
    """
    Load the secret key from a file.
    :return: Crypto key base.
    """
    try:
        with open("secret.key", "r") as reader:
            return reader.readline()
    except IOError as e:
        return e


def encrypt_message(message):
    """
    Encrypts (AES256) given credentials with the given master key.
    :param message: Message to encrypt.
    :return: Encrypted message.
    """
    salt = secrets.token_bytes(BLOCK_SIZE)
    key_base = load_crypto_key_base_from_file()
    kdf = PBKDF2(key_base, salt, 64, 1000)
    private_key = kdf[:32]
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(message, 'utf-8'))

    try:
        with open("encrypted_message.bin", "wb") as output:
            [output.write(x) for x in (salt, cipher_config.nonce, tag, cipher_text)]
        return True
    except IOError as e:
        return e


def decrypt_message(encryption_file):
    """
    Decrypts given credentials with the given master key.
    :param encryption_file: File containing encryption parameters and the cipher text.
    :return: Decrypted message.
    """
    try:
        with open(encryption_file, "rb") as reader:
            salt, nonce, tag,  cipher_text = [reader.read(x) for x in (16, 16, 16, -1)]
    except IOError as e:
        return e

    key_base = load_crypto_key_base_from_file()
    kdf = PBKDF2(key_base, salt, 64, 1000)
    private_key = kdf[:32]
    cipher_config = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    decrypted = cipher_config.decrypt_and_verify(cipher_text, tag).decode('utf-8')
    return decrypted


def hash_key(master_password):
    """
    Creates a hash of the given master password to be stored in the database. PBKDF2-SHA256 is used.
    :param master_password: Key used to log in to the password manager.
    :return: Hash of the given master key.
    """
    salt = secrets.token_bytes(32)
    derived_key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    digest = derived_key.hex()
    return digest


def generate_password(length=12):
    """
    Generate a strong password.
    :param length: Length of the password (minimum length is 12 characters).
    :return: Password string.
    """
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits
    symbols = string.punctuation

    all = lower + upper + num + symbols
    pwd_suggestion = random.sample(all, length)

    generated_password = "".join(pwd_suggestion)
    return generated_password
