import base64
import json
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256

class SpectreError(Exception):
    pass

class SpectreRecord:

    def __init__(self, site: str, counter: str, scheme: bool, check: str):
        self.site = site
        self.counter = counter
        self.scheme = scheme
        self.check = check

    def serialize(self) -> dict:
        return {'counter' : self.counter, 'scheme' : self.scheme, 'check': self.check}

    def update(self, counter, scheme, check):
        self.counter = counter
        self.scheme = scheme
        self.check = check

class SpectreRecordsPool:

    def __init__(self):
        self.is_updated = False
        self.records = {}

    def update(self, site, counter = 1, scheme = False, check = ''):
        if site in self.records:
            current = self.records[site].serialize()
            if current['counter'] != counter or current['scheme'] != scheme:
                self.records[site].update(counter, scheme, check)
                self.is_updated = True
        else:
            self.records[site] = SpectreRecord(site, counter, scheme, check)
            self.is_updated = True

    def serialize(self):
        return {record: self.records[record].serialize() for record in self.records}

    def unserialize(self, serialized: dict):
        self.records = {}
        for site in serialized:
            self.records[site] = SpectreRecord(site, **serialized[site])

    def erase(self):
        self.records = {}
        self.is_updated = True

    def clear(self):
        self.records = {}
        self.is_updated = False

    def get_parameters(self, site):
        parameters = self.records[site].serialize()
        del parameters['check']
        return parameters

    def get_all_parameters(self):
        return {site : self.get_parameters(site) for site in self.records}

    def check(self, site, check) -> bool:
        if site in self.records:
            return check == self.records[site].check
        else:
            return True

class Spectre:

    PURPOSE_KEYS = {
        'authentication' : b'com.lyndir.masterpassword',
        'identification' : b'com.lyndir.masterpassword.login',
        'recovery'       : b'com.lyndir.masterpassword.answer'
    }

    SCRYPT_PARAMETERS = {'N' : 32768, 'r' : 8, 'p' : 2}

    TEMPLATES = {
        "max"   : ["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"],
        "long"  : ["CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv",
                    "CvcvCvccnoCvcv", "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno", "CvccnoCvccCvcv", "CvccCvccnoCvcv",
                    "CvccCvccCvcvno", "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno"],
        "medium": ["CvcnoCvc", "CvcCvcno"],
        "short" : ["Cvcn"],
        "basic" : ["aaanaaan", "aannaaan", "aaannaaa"],
        "pin"   : ["nnnn"],
        "name"  : ["cvccvcvcv"],
        "phrase": ["cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv"]
    }

    CHARACTERS_CLASSES = {'V': "AEIOU",
                          'C': "BCDFGHJKLMNPQRSTVWXYZ",
                          'v': "aeiou",
                          'c': "bcdfghjklmnpqrstvwxyz",
                          'A': "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
                          'a': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
                          'n': "0123456789",
                          'o': "@&%?,=[]_:-+*$#!'^~;()/.",
                          'x': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
                          ' ': " "}
    
    USER_KEY_SIZE = SHA256.block_size

    def __init__(self):
        self.pool = SpectreRecordsPool()
        self.records_file = None

    def load_records(self, records_file: str):
        self.records_file = records_file
        self.pool.clear()
        try:
            with open(self.records_file, 'r') as f:
                self.pool.unserialize(json.load(f))
        except Exception as e:
            print('Failed to load records file. Erase it.', e)
            self.pool.erase()

    def get_records_parameters(self):
        return self.pool.get_all_parameters()

    def save_records(self):
        if self.records_file:
            with open(self.records_file, 'w') as f:
                json.dump(self.pool.serialize(), f, indent=4)

    def is_updated(self) -> bool:
        return (self.records_file != None) and (self.pool.is_updated)

    def auto_compute_password(self, username, secret, site: str):
        try:
            parameters = self.pool.get_parameters(site)
        except KeyError:
            raise SpectreError('Cannot auto-generate password, unknown site')
        return self.compute_password(username=username, secret=secret, site=site, **parameters)

    def buffer_str(self, value: str):
        return value.encode('ascii')

    def buffer_int(self, value: int):
        return value.to_bytes(4, 'big')

    def buffer_len_str(self, value: str):
        return self.buffer_int(len(value)) + self.buffer_str(value)

    def compute_password(self, username, secret, site, counter = 1, scheme = 'max'):

        # Store attributes
        self.username = username
        self.site = site
        self.counter = counter
        self.scheme = scheme

        # Compute user key 
        user_key_salt = Spectre.PURPOSE_KEYS['authentication'] + self.buffer_len_str(username)
        user_key = scrypt(self.buffer_str(secret), user_key_salt, Spectre.USER_KEY_SIZE, Spectre.SCRYPT_PARAMETERS['N'], Spectre.SCRYPT_PARAMETERS['r'], Spectre.SCRYPT_PARAMETERS['p'])

        # Compute site key
        site_key_salt = Spectre.PURPOSE_KEYS['authentication'] + self.buffer_len_str(site) + self.buffer_int(counter)
        site_key = HMAC.new(user_key, digestmod=SHA256).update(site_key_salt).digest()

        # Retrieve template to use from scheme and user_key first byte
        if not scheme in Spectre.TEMPLATES:
            raise SpectreError('Invalid scheme')
        template_index = int(site_key[0])
        template = Spectre.TEMPLATES[scheme][template_index % len(Spectre.TEMPLATES[scheme])]

        # Compute password against template
        password = ''
        for c in range(len(template)):
            seed_byte = int(site_key[c + 1])
            characters_class = Spectre.CHARACTERS_CLASSES[template[c]]
            password = password + characters_class[seed_byte % len(characters_class)]

        # Compute verification proof
        check = SHA256.new(self.buffer_str(password)).hexdigest()[0:2]

        # Update pool with this update
        self.pool.update(site, counter, scheme, check)

        # Check match with current pool
        if not self.pool.check(site, check):
            raise SpectreError('Password checking detected mismatch. Verify your master password')

        return password
