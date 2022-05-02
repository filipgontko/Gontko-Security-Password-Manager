import hashlib
import secrets
import random
import string
import os
import pwnedpasswords
import pyotp
import qrcode.image.svg

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from backend.my_logger import logger

BLOCK_SIZE = 16
OTP_BASE = "JBSWY3DPEHPK3PXP"


def generate_crypto_key_base(master=False):
    """
    Generate and write into a file a crypto key base that will be used to encrypt and decrypt messages.
    Returns:
        None
    """
    if not (key_exists()):
        key = generate_password(25)
        file_name = "secret.key"
        if master:
            file_name = "master_secret.key"
        try:
            with open(file_name, "w") as crypto_key_file:
                crypto_key_file.write(key)
        except IOError as e:
            return None


def key_exists(master=False):
    """
    Validate if a key exists
    Returns:
         True if the key exists, False otherwise
    """
    file_name = "secret.key"
    if master:
        file_name = "master_secret.key"
    return os.path.isfile(file_name)


def load_crypto_key_base_from_file(master=False):
    """
    Load the secret key from a file.
    Returns:
         Crypto key base.
    """
    try:
        file_name = "secret.key"
        if master:
            file_name = "master_secret.key"
        with open(file_name, "r") as reader:
            return reader.readline()
    except IOError as e:
        return None


def encrypt_message(message, password):
    """
    Encrypts (AES256) given credentials with a master key consisting of a master password and a key file.
    Args:
        message: Message to encrypt.
        password: Master password.

    Returns:
        Encrypted message.
    """
    salt = secrets.token_bytes(BLOCK_SIZE)
    if not key_exists():
        generate_crypto_key_base()
    key_base = load_crypto_key_base_from_file() + password
    kdf = PBKDF2(key_base, salt, 64, 1000)
    key = kdf[:32]
    cipher_config = AES.new(key, AES.MODE_GCM)

    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(message, 'utf-8'))

    try:
        output = salt + cipher_config.nonce + tag + cipher_text
        return output
    except Exception as e:
        return None


def decrypt_message(encrypted_message, password):
    """
    Decrypts given credentials with the given master key.
    Args:
        encrypted_message: File containing encryption parameters and the cipher text.
        password: Master password.

    Returns:
        Decrypted message.
    """
    try:
        salt, nonce, tag = [encrypted_message[i:i+16] for i in range(0, 47, 16)]
        chunk_size = len(encrypted_message) - 48
        cipher_text = [encrypted_message[i:len(encrypted_message)] for i in range(48, len(encrypted_message), chunk_size)]
    except IOError as e:
        return None

    key_base = load_crypto_key_base_from_file() + password
    kdf = PBKDF2(key_base, salt, 64, 1000)
    key = kdf[:32]
    cipher_config = AES.new(key, AES.MODE_GCM, nonce=nonce)

    decrypted = cipher_config.decrypt_and_verify(cipher_text[0], tag).decode('utf-8')
    return decrypted


def create_master_key(master_password):
    """
    Creates a salted hash of the given master password to be stored in the database. PBKDF2-SHA256 is used.
    Returns:
         Hash of the given master key.
    """
    salt = secrets.token_bytes(32)
    if not key_exists():
        generate_crypto_key_base(master=True)
    key_base = load_crypto_key_base_from_file(master=True)
    master_key = master_password + key_base
    derived_key = hashlib.pbkdf2_hmac('sha256', master_key.encode(), salt, 100000)
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
    Returns:
         Hash of the salted master password.
    """
    try:
        with open("master_key_salt.bin", "rb") as file:
            salt = file.read()
    except IOError as e:
        return None

    key_base = load_crypto_key_base_from_file(master=True)
    master_key = master_password + key_base
    derived_key = hashlib.pbkdf2_hmac('sha256', master_key.encode(), salt, 100000)
    digest = derived_key.hex()
    return digest


def generate_password(length=12):
    """
    Generate a strong password.
    Args:
        length: Length of the password (minimum length is 12 characters).

    Returns:
        Password string.
    """
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits
    symbols = string.punctuation

    all = lower + upper + num + symbols
    pwd_suggestion = random.sample(all, length)

    generated_password = "".join(pwd_suggestion)

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


def generate_otp_url(email):
    """
    Generate OTP URL that can be used with Google Authenticator.
    Args:
        email: E-mail of the user

    Returns:
        URL that can be converted to QR and used in Google Authenticator app.
    """
    return pyotp.totp.TOTP(OTP_BASE).provisioning_uri(name=email, issuer_name='Gontko Security Password Manager')


def generate_otp_qr_for_auth(otp_url):
    """
    Generate a QR code for Google Authenticator app.
    Args:
        otp_url: Url of the OTP
    """
    try:
        img = qrcode.make(otp_url, image_factory=qrcode.image.svg.SvgImage)
        with open('user_qr.svg', 'wb') as qr:
            img.save(qr)
    except Exception as e:
        logger.error("Exception occurred during generation OTP QR code. - {}".format(e))


def compare_totp(google_otp):
    """
    Compares the user entered OTP from Google Authenticator against the locally calculated OTP.
    Args:
        google_otp: Google Authenticator code

    Returns:
        True if matches, False otherwise.
    """
    totp = pyotp.TOTP(OTP_BASE)
    return totp.now() == google_otp
