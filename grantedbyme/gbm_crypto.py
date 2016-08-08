#
# The MIT License (MIT)
#
# Copyright (c) 2016 GrantedByMe
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""
GrantedByMe Cryptographic helper
.. moduleauthor:: GrantedByMe <info@grantedby.me>
"""
# -*- coding: utf-8 -*-

import base64
import json
import os
import random
import string
import hashlib
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from enum import Enum


class JWEEncType(Enum):
    """JSONWebEncryptionEncryptionType Enumerations"""
    A128CBC_HS256 = 1   # AES_128_CBC_HMAC_SHA_256
    A192CBC_HS256 = 2   # AES_192_CBC_HMAC_SHA_256
    A1256CBC_HS256 = 3  # AES_256_CBC_HMAC_SHA_256
    A128GCM = 4         # AES GCM using 128-bit key
    A192GCM = 5         # AES GCM using 192-bit key
    A256GCM = 6         # AES GCM using 256-bit key


class JWEAlgType(Enum):
    """JSONWebEncryptionAlgorithmType Enumerations"""
    RSA1_5 = 1     # RSAES-PKCS1-v1_5
    RSA_OAEP = 2   # RSAES OAEP using default parameters
    A128KW = 3     # AES Key Wrap with default initial value using 128-bit key
    A192KW = 4     # AES Key Wrap with default initial value using 192-bit key
    A256KW = 5     # AES Key Wrap with default initial value using 256-bit key
    A128GCMKW = 6  # AES GCM using 128-bit key
    A192GCMKW = 7  # AES GCM using 192-bit key
    A256GCMKW = 8  # AES GCM using 256-bit key


class JWSAlgType(Enum):
    """JSONWebSignatureAlgorithmType Enumerations"""
    HS256 = 1   # HMAC using SHA-256
    HS384 = 2   # HMAC using SHA-384
    HS512 = 3   # HMAC using SHA-512
    RS256 = 4   # RSASSA-PKCS1-v1_5 using SHA-256
    RS384 = 5   # RSASSA-PKCS1-v1_5 using SHA-384
    RS512 = 6   # RSASSA-PKCS1-v1_5 using SHA-512
    ES256 = 7   # ECDSA using P-256 and SHA-256
    ES384 = 8   # ECDSA using P-384 and SHA-384
    ES512 = 9   # ECDSA using P-521 and SHA-512
    PS256 = 10  # RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS384 = 11  # RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS512 = 12  # RSASSA-PSS using SHA-512 and MGF1 with SHA-512


class SecurityException(Exception):
    """
    Raised when a Security check has been failed (invalid input, signature, etc.)
    """
    pass


class GBMCrypto(object):
    """GBMCrypto class"""

    def __init__(self):
        """Constructor"""
        raise Exception('Static class instantiation error')

    ########################################
    # HELPERS
    ########################################

    @classmethod
    def random_string(cls, length=128):
        """
        Return a random string by given length which defaults to 128 chars.
        :param length:
        :return:
        """
        return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(length))

    @classmethod
    def sha512(cls, message):
        """
        Hashes an input using SHA-512.
        Additionally normalizes line endings of input before hashing to handle unix / win compatibility issues.
        :param message:
        :return:
        """
        if isinstance(message, str):
            message = message.replace('\r\n', '\n')
            message = message.replace('\r', '\n')
            message = message.encode('utf-8')
        return hashlib.sha512(message).hexdigest()

    ########################################
    # ASYMMETRIC (RSA)
    ########################################

    @classmethod
    def generate_keypair(cls):
        """RSA keypair generator"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    @classmethod
    def serialize_key(cls, key):
        """RSA key serializer"""
        if isinstance(key, rsa.RSAPrivateKey):
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        if isinstance(key, rsa.RSAPublicKey):
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return None

    @classmethod
    def serialize_key_der(cls, key):
        """RSA public key DER serializer"""
        if isinstance(key, rsa.RSAPublicKey):
            return base64.b64encode(key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.PKCS1
            ))
        return None

    @classmethod
    def load_private_key(cls, private_key):
        """RSA private key PEM loader"""
        return serialization.load_pem_private_key(private_key, password=None, backend=default_backend())

    @classmethod
    def load_public_key(cls, public_key):
        """RSA public key PEM/DER loader"""
        if not public_key.decode('utf-8').startswith('-----'):
            return serialization.load_der_public_key(base64.b64decode(public_key), backend=default_backend())
        return serialization.load_pem_public_key(public_key, backend=default_backend())

    @classmethod
    def encrypt_rsa(cls, public_key, message_bytes):
        """RSA encrypt"""
        return public_key.encrypt(message_bytes,
                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),
                                               label=None))

    @classmethod
    def decrypt_rsa(cls, private_key, cipher_bytes):
        """RSA decrypt"""
        return private_key.decrypt(cipher_bytes,
                                   padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),
                                                label=None))

    @classmethod
    def sign_rsa(cls, private_key, message_bytes):
        """RSA sign"""
        signer = private_key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512())
        signer.update(message_bytes)
        return signer.finalize()

    @classmethod
    def verify_rsa(cls, public_key, message_bytes, signature_bytes):
        """RSA verify"""
        verifier = public_key.verifier(signature_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64),
                                       hashes.SHA512())
        verifier.update(message_bytes)
        return verifier.verify()

    @classmethod
    def encrypt_rsa_json(cls, public_pem, private_pem, source, algorithm=None):
        """Encrypt and sign message dictionary key pair"""
        if public_pem is None or private_pem is None or source is None:
            raise SecurityException('TypeError')
        if isinstance(source, dict):
            message_text = json.dumps(source)
        else:
            message_text = source
        message_bytes = message_text.encode('utf-8')
        public_key = GBMCrypto.load_public_key(public_pem.encode('utf-8'))
        private_key = GBMCrypto.load_private_key(private_pem.encode('utf-8'))
        payload = GBMCrypto.encrypt_rsa(public_key, message_bytes)
        if algorithm == JWSAlgType.RS512.name:
            signer = private_key.signer(padding.PKCS1v15(), hashes.SHA512())
            signer.update(message_bytes)
            signature = signer.finalize()
        else:
            signature = GBMCrypto.sign_rsa(private_key, message_bytes)
        return base64.b64encode(payload).decode('utf-8'), base64.b64encode(signature).decode('utf-8')

    @classmethod
    def decrypt_rsa_json(cls, public_pem, private_pem, payload, signature, algorithm=None):
        """Decrypt message using key pair"""
        if public_pem is None or private_pem is None or payload is None or signature is None:
            raise SecurityException('TypeError')
        public_key = GBMCrypto.load_public_key(public_pem.encode('utf-8'))
        private_key = GBMCrypto.load_private_key(private_pem.encode('utf-8'))
        message_bytes = GBMCrypto.decrypt_rsa(private_key, base64.b64decode(payload))
        if algorithm == JWSAlgType.RS512.name:
            try:
                verifier = public_key.verifier(base64.b64decode(signature), padding.PKCS1v15(), hashes.SHA512())
                verifier.update(message_bytes)
                verifier.verify()
            except:
                raise SecurityException('Invalid signature')
        else:
            try:
                # PSS/MGF1/SHA512
                GBMCrypto.verify_rsa(public_key, message_bytes, base64.b64decode(signature))
            except:
                raise SecurityException('Invalid signature')
        message_text = message_bytes.decode('utf-8')
        result = json.loads(message_text)
        return result

    ########################################
    # SYMMETRIC (AES+HMAC)
    ########################################

    @classmethod
    def encrypt_aes(cls, message, key=None, iv=None):
        """Encrypts an input using AES encryption."""
        if message is None:
            raise SecurityException('TypeError')
        if isinstance(message, str):
            message = message.encode('utf-8')
        padder = PKCS7(128).padder()
        message = padder.update(message) + padder.finalize()
        if key is None:
            key = os.urandom(32)
        elif isinstance(key, str):
            key = key.encode('utf-8')
        if iv is None:
            iv = os.urandom(16)
        elif isinstance(iv, str):
            iv = iv.encode('utf-8')
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        result = encryptor.update(message) + encryptor.finalize()
        return result, key, iv

    @classmethod
    def decrypt_aes(cls, message, key, iv):
        """Decrypts an input using AES encryption"""
        if message is None or key is None or iv is None:
            raise SecurityException('TypeError')
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        result = decryptor.update(message) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        result = unpadder.update(result) + unpadder.finalize()
        return result

    @classmethod
    def sign_aes(cls, message, key):
        """Signs an input using HMAC/SHA-256"""
        if message is None or key is None:
            raise SecurityException('TypeError')
        if isinstance(message, str):
            message = message.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()

    @classmethod
    def verify_aes(cls, message, key, signature):
        """Verifies a HMAC signature"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(signature, str):
            signature = signature.encode('utf-8')
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        h.verify(signature)

    @classmethod
    def encrypt_aes_json(cls, source):
        """Encrypt message dictionary"""
        if isinstance(source, dict):
            message_text = json.dumps(source)
        else:
            message_text = source
        result = GBMCrypto.encrypt_aes(message_text.encode('utf-8'))
        signature_bytes = GBMCrypto.sign_aes(message_text.encode('utf-8'), result[1])
        cipher_b64 = base64.b64encode(result[0]).decode('utf-8')
        key_b64 = base64.b64encode(result[1]).decode('utf-8')
        iv_b64 = base64.b64encode(result[2]).decode('utf-8')
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
        return cipher_b64, key_b64, iv_b64, signature_b64

    @classmethod
    def decrypt_aes_json(cls, message, key, iv, signature):
        """Decrypt message dictionary"""
        if message is None or key is None or iv is None:
            raise SecurityException('TypeError')
        message = base64.b64decode(message)
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)
        message_bytes = GBMCrypto.decrypt_aes(message, key, iv)
        signature = base64.b64decode(signature)
        GBMCrypto.verify_aes(message_bytes, key, signature)
        message_text = message_bytes.decode('utf-8')
        result = json.loads(message_text)
        return result

    ########################################
    # FERNET
    #
    # Fernet is built on top of a number of standard cryptographic primitives.
    #
    # Specifically it uses:
    # - AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding.
    # - HMAC using SHA256 for authentication.
    # - Initialization vectors are generated using os.urandom().
    ########################################

    @classmethod
    def encrypt_fernet(cls, message, secret):
        """Fernet encryption"""
        if message is None or secret is None:
            raise SecurityException('TypeError')
        if isinstance(message, str):
            message = message.encode('utf-8')
        if isinstance(secret, str):
            secret = secret.encode('utf-8')
        f = Fernet(secret)
        return f.encrypt(message)

    @classmethod
    def decrypt_fernet(cls, message, secret):
        """Fernet decryption"""
        if message is None or secret is None:
            raise SecurityException('TypeError')
        if isinstance(message, str):
            message = message.encode('utf-8')
        if isinstance(secret, str):
            secret = secret.encode('utf-8')
        f = Fernet(secret)
        return f.decrypt(message)

    @classmethod
    def encrypt_fernet_string(cls, message, secret):
        """Fernet string encryption"""
        return base64.urlsafe_b64encode(GBMCrypto.encrypt_fernet(message, secret)).decode('utf-8')

    @classmethod
    def decrypt_fernet_string(cls, message, secret):
        """Fernet string decryption"""
        try:
            plain_message = base64.urlsafe_b64decode(message)
        except:
            return None
        if not plain_message:
            return None
        return GBMCrypto.decrypt_fernet(plain_message, secret).decode('utf-8')

    ########################################
    # Compound Wrapper
    ########################################

    @classmethod
    def encrypt_compound(cls, data, public_key, private_key, algorithm=None, is_optional_compound=True):
        """Encrypts and signs an input using RSA and optionally AES/HMAC encryption and signature"""
        # use default RSA algorithm if none specified
        if not algorithm:
            algorithm = JWSAlgType.PS512.name
        # serialize dictionary to json string
        plain_text = json.dumps(data)
        # Message length is small enough to use signed RSA encryption only
        if len(plain_text) < 215 and is_optional_compound:
            rsa_tuple = GBMCrypto.encrypt_rsa_json(public_key, private_key, plain_text, algorithm)
            return {'payload': rsa_tuple[0], 'signature': rsa_tuple[1]}
        # Use signed AES encryption using keys wrapped in signed RSA encryption
        aes_tuple = GBMCrypto.encrypt_aes_json(plain_text)
        aes_dict = {
            'cipher_key': aes_tuple[1],
            'cipher_iv': aes_tuple[2],
            'signature': aes_tuple[3],
            'timestamp': int(time.time())
        }
        rsa_tuple = GBMCrypto.encrypt_rsa_json(public_key, private_key, aes_dict, algorithm)
        return {'payload': rsa_tuple[0], 'signature': rsa_tuple[1], 'message': aes_tuple[0]}

    @classmethod
    def decrypt_compound(cls, data, public_key, private_key):
        """Decrypts and verifies an input using RSA and optional AES encryption with signature"""
        if not data or 'payload' not in data or 'signature' not in data:
            raise SecurityException('TypeError')
        if 'alg' not in data:
            data['alg'] = JWSAlgType.PS512.value
        cipher_json = GBMCrypto.decrypt_rsa_json(public_key,
                                             private_key,
                                             data['payload'],
                                             data['signature'],
                                             data['alg'])
        # return RSA decrypted object if not encrypted using AES (non-compound asymmetric)
        if 'message' not in data and 'cipher_key' not in cipher_json and 'cipher_iv' not in cipher_json and 'signature' not in cipher_json:
            return cipher_json
        return GBMCrypto.decrypt_aes_json(data['message'],
                                          cipher_json['cipher_key'],
                                          cipher_json['cipher_iv'],
                                          cipher_json['signature'])
