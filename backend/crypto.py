import hashlib
import secrets
import random
import string
import base64

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def generate_crypto_key_base():
    """
    Generate and write into a file a crypto key base that will be used to encrypt and decrypt messages.
    """
    if not (key_exists()):
        key = generate_password(25)
        with open("secret.key", "w") as crypto_key_file:
            crypto_key_file.write(key)


def key_exists():
    """
    Validate if a key exists
    :return: True if the key exists, False otherwise
    """
    try:
        if open("secret.key", "r").read():
            return True
    except:
        return False


def load_crypto_key_base_from_file():
    """
    Load the secret key from a file.
    :return: Crypto key base.
    """
    return open("secret.key", "r").read()


def get_crypto_key():
    """
    Get the crypto key used to encrypt/decrypt the message.
    :return: The secret key.
    """
    password = load_crypto_key_base_from_file()
    salt = Random.get_random_bytes(BLOCK_SIZE)
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key


def encrypt_message(message):
    """
    Encrypts (AES256) given credentials with the given master key.
    :param message: Message to encrypt.
    :return: Encrypted message.
    """
    key = get_crypto_key()
    raw = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt_message(message):
    """
    Decrypts given credentials with the given master key.
    :param message: Message to encrypt.
    :return: Decrypted message.
    """
    key = get_crypto_key()
    enc = base64.b64decode(message)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


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
