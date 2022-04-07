import hashlib
import secrets
import random
import string

from cryptography.fernet import Fernet


def encrypt_message(message, master_key):
    """
    Encrypts (AES256) given credentials with the given master key.
    :param master_key: Key used to encrypt credentials.
    :param message: Message to encrypt.
    :return: Encrypted message.
    """
    f = Fernet(master_key)
    encoded_credentials = message.encode()
    encrypted = f.encrypt(encoded_credentials)
    return encrypted


def decrypt_message(message, master_key):
    """
    Decrypts given credentials with the given master key.
    :param master_key: Key used to decrypt credentials.
    :param message: Message to encrypt.
    :return: Decrypted message.
    """
    f = Fernet(master_key)
    decrypted = f.decrypt(message)
    return decrypted

# TODO: Find out how to hash with salt and always use the same salt for a specific password. Maybe store salt in DB?
# Follow this standard https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf


def hash_key(master_password):
    """
    Creates a hash of the given master password to be stored in the database. PBKDF2-SHA256 is used.
    :param master_password: Key used to encrypt/decrypt credentials.
    :return: Hash of the given master key.
    """
    salt = secrets.token_bytes(32)
    derived_key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    digest = derived_key.hex()
    print(digest)
    return digest


def generate_password(length):
    """
    Generate a strong password.
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
