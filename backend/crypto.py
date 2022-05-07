import hashlib
import secrets
import random
import string
import os
import pwnedpasswords
import pyotp
import qrcode
import keyring

from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from backend.my_logger import logger

BLOCK_SIZE = 16
NAMESPACE = "gontko-security-password-manager"


def generate_crypto_key_base(keyname):
    """
    Generate and write into a file a crypto key base that will be used to encrypt and decrypt messages.
    Returns:
        None
    """
    if not (key_exists(keyname)):
        try:
            key = generate_password(64)
            keyring.set_password(NAMESPACE, keyname, key)
        except Exception as e:
            return None


def generate_otp_key_base():
    """
    Generate a random_base32 secret compatible with Google Authenticator and other OTP apps.
    Returns:
        Random key in base32
    """
    if not (key_exists("otp.key")):
        try:
            keyring.set_password(NAMESPACE, "otp.key", pyotp.random_base32())
        except Exception as e:
            logger.error("Exception occurred during otp key base generation")


def key_exists(keyname):
    """
    Validate if a key exists
    Returns:
         True if the key exists, False otherwise
    """
    cred = keyring.get_credential(NAMESPACE, keyname)
    return cred is not None


def get_keyring_password(keyname):
    """
    Get a secret stored in a keyring.
    Args:
        keyname: Name of the key

    Returns:
        Secret.
    """
    try:
        cred = keyring.get_credential(NAMESPACE, keyname)
        return cred.password
    except Exception as e:
        logger.error("Exception occurred while getting secret from keyring. {}".format(e))
        return None


def generate_chacha20_key():
    """
    Generate a key for ChaCha20 encryption and store it in a binary file format.
    """
    try:
        key = secrets.token_bytes(32)
        with open("chacha20_key.bin", "wb") as key_output:
            key_output.write(key)
    except Exception as e:
        logger.error("Exception occurred during chacha20 key generation.")


def chacha20_encrypt(secret):
    """
    ChaCha20 encryption used for in memory secrets protection.
    Args:
        secret: Secret to be encrypted.

    Returns:
        Tuple (nonce, ciphertext_b64)
    """
    try:
        with open("chacha20_key.bin", "rb") as file:
            key = file.read()

        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(str.encode(secret))

        nonce = b64encode(cipher.nonce).decode("utf-8")
        ciphertext_b64 = b64encode(ciphertext).decode('utf-8')

        return nonce, ciphertext_b64
    except Exception as e:
        return None


def chacha20_decrypt(secret):
    """
    ChaCha20 encryption used for in memory secrets protection. Decrypts the password tuple
    Args:
        secret: Secret to be decrypted.

    Returns:
        Plaintext secret as a string.
    """
    try:
        with open("chacha20_key.bin", "rb") as file:
            key = file.read()

        nonce = b64decode(secret[0])
        ciphertext = b64decode(secret[1])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext).decode("utf-8")
        return plaintext
    except Exception as e:
        logger.error("Incorrect decryption for in memory secret protection. {}".format(e))


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
    if not key_exists("secret.key"):
        generate_crypto_key_base("secret.key")
    key_base = get_keyring_password("secret.key") + chacha20_decrypt(password)
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

    key_base = get_keyring_password("secret.key") + chacha20_decrypt(password)
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
    if not key_exists("master_secret.key"):
        generate_crypto_key_base("master_secret.key")
    key_base = get_keyring_password("master_secret.key")
    master_key = chacha20_decrypt(master_password) + key_base + os.getlogin()
    derived_key = hashlib.pbkdf2_hmac('sha256', master_key.encode(), salt, 100000)
    digest = derived_key.hex()

    try:
        with open("master_key_salt.bin", "wb") as output:
            output.write(salt)
    except IOError as e:
        return None

    return digest


def recreate_master_password_hash(master_password):
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

    key_base = get_keyring_password("master_secret.key")
    master_key = chacha20_decrypt(master_password) + key_base + os.getlogin()
    derived_key = hashlib.pbkdf2_hmac('sha256', master_key.encode(), salt, 100000)
    digest = derived_key.hex()
    return digest


def generate_password(length=12):
    """
    Generate a strong password.
    Args:
        length: Length of the password (minimum length is 12 characters).
        otp: Optional value to generate OTP key base. Needs to be only lower, upper and num.

    Returns:
        Password string.
    """
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits
    symbols = string.punctuation

    all_chars = lower + upper + num + symbols

    pwd_suggestion = random.sample(all_chars, length)

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
    return pwnedpasswords.check(chacha20_decrypt(password), plain_text=True)


def generate_otp_url(email):
    """
    Generate OTP URL that can be used with Google Authenticator.
    Args:
        email: E-mail of the user

    Returns:
        URL that can be converted to QR and used in Google Authenticator app.
    """
    generate_otp_key_base()
    return pyotp.totp.TOTP(get_keyring_password("otp.key")).provisioning_uri(name=email, issuer_name='Gontko Security Password Manager')


def generate_otp_qr_for_auth(otp_url):
    """
    Generate a QR code for Google Authenticator app.
    Image is saved in png format in images directory.
    Args:
        otp_url: Url of the OTP
    """
    try:
        make_images_dir()

        qr = qrcode.QRCode(
            version=1,
            box_size=10,
            border=5)

        qr.add_data(otp_url)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        with open('images/qr.png', 'wb') as qr:
            img.save(qr)
    except Exception as e:
        logger.error("Exception occurred during generation OTP QR code. - {}".format(e))


def make_images_dir():
    """
    Create images directory if it doesn't exist.
    """
    if not os.path.exists("images"):
        try:
            os.makedirs("images")
        except OSError as e:
            raise e


def compare_totp(google_otp):
    """
    Compares the user entered OTP from Google Authenticator against the locally calculated OTP.
    Args:
        google_otp: Google Authenticator code

    Returns:
        True if matches, False otherwise.
    """
    totp = pyotp.TOTP(get_keyring_password("otp.key"))
    return totp.now() == google_otp
