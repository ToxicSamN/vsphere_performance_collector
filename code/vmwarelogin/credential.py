

import platform
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# MUST USE PYTHON 3.5
# Python 3.6 doesn't seem to work right now


class CustomObject(object):
    """ Because I came from powershell I was really spoiled with New-Object PSObject
    So I created a class that acts similar in which I can add and remove properties.

     TODO:
    """

    def __init__(self, property={}):
        for k, v in property.items():
            setattr(self, k, v)

    def add_property(self, property):
        for k, v in property.items():
            setattr(self, k, v)

    def remove_property(self, property_name):
        delattr(self, property_name)


class CryptoKey(object):
    """
    This is a custom class for obtaining the crypto key for the credentials. It defaults to the git repo, however,
    a new crypto key should be created for each individual server at the time of RSA Key pair creation.
    This is obviously security by obscurity and not really secure. There isn't a solid way to do this that is 100%
    truly secure.
        TODO to make this better:
            Option 1: devise a setup in which the crypto key is encrypted with RSA Key-pair and stored in the api
              database. When requesting the crypto key from the api the api will use RSA key-pair to decrypt and
              re-encrypt to send back. This eliminates filesystems storage completely.
    """

    if platform.system() == 'Windows':
        file_path = "G:\\secure\\crypto"

    elif platform.system() == 'Linux':
        file_path = "/u01/git_repo/secure/crypto"

    def __init__(self, file_path=''):
        if file_path:
            self.file_path = file_path

        self.crypto_key = Encryption().md5(self.file_path).ByteString
        self.file_path = None


class Credential(object):
    """
    This class is used to create or get a credential set.
    new(): A clear text password is presented to new() and this
     will get encrypted and the encrypted password will be returned.
    get(): An encrypted password is passed as well as a private key and crypto path (md5 bytestring)
     and this wil return the clear test password. this is used for pyVmomi in which you have to pass a clear text
     password to the SmartConnect()
    """

    def __init__(self, credential_type):
        self.credential_type = credential_type
        self.PublickKey = None
        self.encrypted_password = None

    def new(self, public_key, clear_password):
        tmp = Encryption()
        tmp.encrypt(clear_password, public_key)
        clear_password = None
        self.PublickKey = public_key
        self.encrypted_password = tmp.encrypted_message

    def get(self, private_key, encrypted_password, crypto_path=''):
        if crypto_path:
            secret_code = CryptoKey(crypto_path).crypto_key
        else:
            secret_code = CryptoKey().crypto_key

        tmp = Encryption()
        tmp.decrypt(private_key, encrypted_password, secret_code=secret_code)

        return tmp.decrypted_message


class Encryption(object):
    """
    This class does the heavy lifting of encrypting string, decrypting strings, generating RSA Key-pair, or pulling the
    MD5 hash of a file. There is a default secret_code, but shouldn't have to tell you ... never use the default outside
    of development.
    """

    def encrypt(self, privateData, publickey_file, output_file=None):

        if type(privateData) is str:
            privateData = privateData.encode("utf-8")

        pubkey = RSA.import_key(open(publickey_file, 'r').read())
        cipher_rsa = PKCS1_OAEP.new(pubkey)
        encrypted_message = cipher_rsa.encrypt(privateData)

        setattr(self, 'encrypted_message', base64.b64encode(encrypted_message))

    def decrypt(self, private_key_file, encrypted_data, secret_code=None):

        if secret_code:
            private_key = RSA.import_key(open(private_key_file, 'rb').read(), passphrase=secret_code)
        else:
            private_key = RSA.import_key(open(private_key_file, 'rb').read())

        encrypted_data = base64.b64decode(encrypted_data)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        privateData = cipher_rsa.decrypt(encrypted_data)

        setattr(self, 'decrypted_message', str(privateData, "utf-8"))
        chk = None
        try:
            chk = getattr(self, 'encrypted_message')
        except:
            chk = None
            pass

        if chk:
            delattr(self, 'encrypted_message')

    def generate_rsa_key_pair(self, public_file=None, private_file=None,
                              secret_code=b'N-6NZG\xff<\xddL\x85:\xc5\xc4\xa8n'):
        from Crypto.PublicKey import RSA

        key = RSA.generate(2048)

        private, public = key.exportKey(passphrase=secret_code, pkcs=8,
                                        protection="scryptAndAES128-CBC"), key.publickey().exportKey()

        with open(private_file, 'wb') as f:
            f.write(private)
            f.close
        with open(public_file, 'wb') as f:
            f.write(public)
            f.close

        setattr(self, 'PublicKey_file', public_file)
        setattr(self, 'PrivateKey_file', private_file)

    def get_rsa_public_key_from_private_key(self, file_path=None, encrypted_key=None,
                                            secret_code=b'N-6NZG\xff<\xddL\x85:\xc5\xc4\xa8n'):
        from Crypto.PublicKey import RSA

        if file_path:
            encrypted_key = open(file_path, 'rb').read()

        key = RSA.import_key(encrypted_key, passphrase=secret_code)

        setattr(self, 'PublicKey', key.publickey().exportKey())

    def md5(self, fname):
        import hashlib

        hash_md5 = hashlib.md5()

        with open(fname, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
            f.close()
        setattr(self, 'md5', CustomObject(property={'HexString': hash_md5.hexdigest(),
                                                    'ByteString': hash_md5.digest()
                                                    }
                                          )
                )
        return CustomObject(property={'HexString': hash_md5.hexdigest(),
                                      'ByteString': hash_md5.digest()
                                      }
                            )
