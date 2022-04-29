import hashlib
import secrets
import random
import string
import os
import pwnedpasswords

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
            return None


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
        return None


def encrypt_message(message):
    """
    Encrypts (AES256) given credentials with a master key consisting of a master password and a key file.
    :param message: Message to encrypt.
    :return: Encrypted message.
    """
    salt = secrets.token_bytes(BLOCK_SIZE)
    random_string = "KsZQRTFKAfoA2GhWle2K"
    if not key_exists():
        generate_crypto_key_base()
    key_base = load_crypto_key_base_from_file() + random_string
    kdf = PBKDF2(key_base, salt, 64, 1000)
    master_key = kdf[:32]
    cipher_config = AES.new(master_key, AES.MODE_GCM)

    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(message, 'utf-8'))

    try:
        output = salt + cipher_config.nonce + tag + cipher_text
        return output
    except Exception as e:
        return None


def decrypt_message(encrypted_message):
    """
    Decrypts given credentials with the given master key.
    :param encrypted_message: File containing encryption parameters and the cipher text.
    :return: Decrypted message.
    """
    try:
        salt, nonce, tag = [encrypted_message[i:i+16] for i in range(0, 47, 16)]
        chunk_size = len(encrypted_message) - 48
        cipher_text = [encrypted_message[i:len(encrypted_message)] for i in range(48, len(encrypted_message), chunk_size)]
    except IOError as e:
        return None

    random_string = "KsZQRTFKAfoA2GhWle2K"
    key_base = load_crypto_key_base_from_file() + random_string
    kdf = PBKDF2(key_base, salt, 64, 1000)
    master_key = kdf[:32]
    cipher_config = AES.new(master_key, AES.MODE_GCM, nonce=nonce)

    decrypted = cipher_config.decrypt_and_verify(cipher_text[0], tag).decode('utf-8')
    return decrypted


def create_master_key(master_password):
    """
    Creates a salted hash of the given master password to be stored in the database. PBKDF2-SHA256 is used.
    :return: Hash of the given master key.
    """
    salt = secrets.token_bytes(32)
    derived_key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    digest = derived_key.hex()

    try:
        with open("master_key_salt.bin", "wb") as output:
            output.write(salt)
    except IOError as e:
        return None

    return digest


def compare_master_password_hash(master_password):
    """
    Compares the hash of the given master password to the hash of the saved master password hash.
    :return: Hash of the salted master password.
    """
    try:
        with open("master_key_salt.bin", "rb") as file:
            salt = file.read()
    except IOError as e:
        return None

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
    # TODO: Check if pwd has been pawned.
    return generated_password


def check_password_strength(password):
    """
    Check password strength.
    A password is considered strong if:
        12 characters length or more
        Does not repeat characters ('aaaaaaaaaaaa')
    Args:
        password: Password to check.

    Returns:
        weak, moderate, strong or very strong.
    """
    strength_word = ""

    if len(password) < 8:
        strength_word = "Weak"

    if 8 <= len(password) < 12:
        strength_word = "Moderate"

    if 12 <= len(password) < 20:
        strength_word = "Strong"

    if 20 <= len(password) <= 64:
        strength_word = "Very Strong"

    return strength_word


def check_if_pwned(password):
    """
    Check if password appears in a database of pawned credentials using k-anonymity.
    This allows us to only provide the first 5 characters of the SHA-1 hash of the password in question.
    The API then responds with a list of SHA-1 hash suffixes with that prefix.
    No plaintext passwords ever leave your machine using pwnedpasswords.
    Args:
        password: Password to check

    Returns:
        True if found, False otherwise.
    """
    return pwnedpasswords.check(password, plain_text=True)
