from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsapadding
from cryptography.hazmat.primitives import serialization
import constants

DEBUG_PRINT = False


def test_MyEncrypt_Decrypt():
    print("Testing encrypt(decrypt(\"Hello World!\"))")
    enc_key = urandom(constants.AES_KEYSIZE)
    hmac_key = urandom(constants.AES_KEYSIZE)

    plaintext = b"Hello World!"

    (tag, ct, iv) = MyEncrypt(plaintext, enc_key, hmac_key)

    print("ciphertext:", ct)
    print("tag:", tag)

    decryptedtext = MyDecrypt(ct, enc_key, hmac_key, iv, tag)

    print("result:", decryptedtext)
    print("Matches:", plaintext == decryptedtext)


def MyEncrypt(message, enc_key, hmac_key):
    """
    Generates a 16 byte IV and encrypts the message using key and IV in AES CBC mode.
    :param message: 
    :param enc_key: 
    :param hmac_key: 
    :raises ValueError: if len(key) < 32
    :return: (tag, ciphertext, IV)
    """

    # ensure that len(key) >= 32
    if len(enc_key) < 32:
        raise ValueError("key must be at least 32 bytes long")

    # pad message
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message)

    padded_message += padder.finalize()

    # encrypt padded_message
    backend = default_backend()
    iv = urandom(constants.AES_IVSIZE)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_message) + encryptor.finalize()

    # HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ct)
    tag = h.finalize()

    return tag, ct, iv


def MyDecrypt(ciphertext, enc_key, hmac_key, iv, tag):
    """
    Decrypts ciphertext using key and iv in AES CBC mode.
    :param ciphertext:
    :param enc_key: 
    :param hmac_key: 
    :param iv:
    :param tag:
    :raises cryptography.exceptions.InvalidSignature: if tag does not match digest
    :return: plaintext
    """

    # HMAC verify
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(tag)

    # decrypt ciphertext
    backend = default_backend()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    decrypter = cipher.decryptor()
    padded_plaintext = decrypter.update(ciphertext) + decrypter.finalize()

    # unpad padded_plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()

    return plaintext


def MyFileEncrypt(filepath):
    """
    Generates a 32 byte key. Reads the file at filepath, encrypts the contents, and returns them.
    :param filepath: 
    :return: (ciphertext, IV, HMAC tag, encryption key, HMAC key)
    """

    enc_key = urandom(constants.AES_KEYSIZE)
    hmac_key = urandom(constants.AES_KEYSIZE)

    print("key:", enc_key)

    with open(filepath, 'rb') as file:
        contents = file.read()

        (tag, ciphertext, iv) = MyEncrypt(contents, enc_key, hmac_key)

    return ciphertext, iv, tag, enc_key, hmac_key


def MyFileDecrypt(filepath, ciphertext, enc_key, hmac_key, iv, tag):
    """
    Decrypts the ciphertext and writes the plaintext to a file at filepath. Also returns the plaintext.
    :param filepath: 
    :param enc_key: 
    :param hmac_key: 
    :param iv: 
    :param tag: 
    """

    plaintext = MyDecrypt(ciphertext, enc_key, hmac_key, iv, tag)

    with open(filepath, 'wb') as file:
        file.write(plaintext)

    return plaintext


def GenerateRSAKey():
    """
    Generates a new RSA public and private keypair
    :return: (private key, public key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=constants.RSA_PUBLIC_EXPONENT,
        key_size=constants.RSA_KEYSIZE,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key


def WriteRSAPrivateKey(filepath, key):
    """
    Writes a given private RSA key to a PEM file
    :param filepath: 
    :param key: 
    """
    with open(filepath, "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))


def WriteRSAPublicKey(filepath, key):
    """
    Writes a given public RSA key to a PEM file
    :param filepath: 
    :param key: 
    """
    with open(filepath, "wb") as key_file:
        key_file.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def LoadRSAPrivateKey(filepath):
    """
    Reads a PEM file and loads the private key
    :param filepath: 
    :return: 
    """
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def LoadRSAPublicKey(filepath):
    """
    Reads a PEM file and loads the public key
    :param filepath: 
    :return: 
    """
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return private_key


def MyRSAEncrypt(filepath, RSA_publickey_filepath):
    """
    Reads the contents of a file and encrypts them.
    An AES key is generated and encrypted with the given RSA public key. The encrypted key is returned.
    :param filepath: 
    :param RSA_publickey_filepath: 
    :return: 
    """

    # Encrypt the contents of the file
    (ciphertext, iv, tag, enc_key, hmac_key) = MyFileEncrypt(filepath)

    if (DEBUG_PRINT):
        print('(encrypt) enc_key (a):', enc_key)
        print('(encrypt) hmackey (a):', hmac_key)

    # Encrypt the AES keys (enc_key|hmac_key) using the RSA public keyfile
    publickey = LoadRSAPublicKey(RSA_publickey_filepath)
    encrypted_aes_keys = publickey.encrypt(
        enc_key + hmac_key,

        rsapadding.OAEP(
            mgf=rsapadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_aes_keys, ciphertext, iv, tag


def MyRSADecrypt(filepath, encrypted_aes_keys, ciphertext, iv, tag, RSA_privatekey_filepath):
    """
    Decrypts the ciphertext using an encrypted AES key and RSA private key and writes the result to a file at filepath.
    Also returns the plaintext
    :param filepath: 
    :param encrypted_aes_keys: 
    :param ciphertext: 
    :param iv: 
    :param tag: 
    :param RSA_privatekey_filepath: 
    :return: 
    """

    # Decrypt the AES keys using the RSA private keyfile
    privatekey = LoadRSAPrivateKey(RSA_privatekey_filepath)
    keys = privatekey.decrypt(
        encrypted_aes_keys,

        rsapadding.OAEP(
            mgf=rsapadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Pull enc_key and hmac_key out
    enc_key = keys[0:32]
    hmac_key = keys[32:64]

    if (DEBUG_PRINT):
        print('(decrypt) enc_key (a):', enc_key)
        print('(decrypt) hmackey (a):', hmac_key)

    # Decrypt ciphertext and write it to the file
    plaintext = MyFileDecrypt(filepath, ciphertext, enc_key, hmac_key, iv, tag)

    return plaintext
