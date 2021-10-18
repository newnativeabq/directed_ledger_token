import hashlib
import base64
import logging

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def base10(obj):
    """
    Converts some hash into base 10.
    """
    target = int(obj, 16)
    return target


def baseQ(n, b):
    """
    Convert base 10 into base b.
    """
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]


def getHash(ctr):
    """
    Stringify ctr and sha3 512 hash then hexdigest.
    """
    m = hashlib.sha3_512()
    string = str(ctr).encode('utf-8')
    m.update(bytes(string))
    ctr_hash = m.hexdigest()
    return ctr_hash



class Wallet():

    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    
    @property
    def pub_key_str(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')


    def encrypt(self, m:str):
        cipher_text_bytes = self.public_key.encrypt(
            plaintext=m.encode('utf-8'),
            padding = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        return base64.urlsafe_b64encode(cipher_text_bytes)


    def sign(self, m: str) -> str:
        signature = self.private_key.sign(
            m.encode('utf-8'),
            padding.PSS(
                padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return base64.urlsafe_b64encode(signature)


    def decrypt(self, m: bytes):
        pass