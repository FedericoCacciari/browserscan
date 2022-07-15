import os
import sys
import sqlite3
import win32crypt
import json
import base64
import csv
from shutil import copyfile
from Crypto.Cipher import AES
from functools import cached_property

def find_chromium_browsers():
    #Function to find all the chromium browsers on the system,
    #it was gently stolen by the browserscan code:
    #Thx, repo info: https://github.com/kdirectorate/browserscan
    #Now back to coding.
    LOCAL_STATE_NAME = "Local State"
    LOGIN_DATA_NAME = "Default\\Login Data"
    browsers = {}
    sourcedir = os.path.expanduser('~') + "\\AppData\\Local\\"
    for publisher in os.listdir(sourcedir):
        pubdir = os.path.join(sourcedir,publisher)
        if os.path.exists(os.path.join(pubdir, "User Data", LOCAL_STATE_NAME)) and \
            os.path.exists(os.path.join(pubdir, "User Data", LOGIN_DATA_NAME)):
            browsers[publisher] = os.path.join(pubdir, "User Data")
        try:
            for bname in os.listdir(pubdir):
                ls = os.path.join(pubdir,bname,"User Data",LOCAL_STATE_NAME)
                if os.path.exists(ls):
                    ld = os.path.join(pubdir,bname,"User Data",LOGIN_DATA_NAME)
                    if os.path.exists(ld):
                        browsers[publisher+"\\"+bname] = os.path.join(pubdir,bname,"User Data")
        except WindowsError:
            pass
    return browsers



class Chromium:

    CHROME_ENC_VER10_PREFIX = b"v10"
    CHROME_ENC_VER10_PREFIX16 = "v10".encode("UTF-16")
    CHROME_NONCE_LENGTH = int(96 / 8)
    CHROME_OSCRYPT_ENCRYPTEDKEYPREF_NAME = "os_crypt.encrypted_key"
    CHROME_DPAPI_PREFIX = b"DPAPI"
    DPAPI_PREFIX = b"\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB"
    CHROME_DPAPI_PREFIX = b"DPAPI"

    def __init__(self, path):
        self.path = path
    
    @cached_property
    def browser_data(self):
        return self.get_browser_data() 

    @cached_property
    def profiles_name(self):   
        return self.get_profiles()
    
    @cached_property
    def key(self):
        return self.get_key()

    def get_profiles(self) -> list:
        """
        Function to get all the profiles of a Chromium browser.
        """
        profiles = []
        for profile in os.listdir(self.path):
            if profile.startswith("Profile") or profile == "Default":
                profiles.append(profile)
        return profiles

    def get_browser_data(self) -> dict:
        """
        All the settings of a chromium browser are stored in a file,
        called Local State, and, thankfully, all is just store as 
        a json file
        """
        with open(os.path.join(self.path, "Local State"), "r") as f:
            data = json.load(f)
        self.browser_data = data
        return data

    def get_key(self) -> bytes:
        """
        Function to get the key used to encrypt the data.
        """
        # Newer versions of Chrome generate a key to encrypt the user passwords with.
        # Chrome encrypts THAT password on Windows using the Windows DPAPI and then
        # base64 encodes it to store in the browser state file.
        encrypted_key = base64.b64decode(self.browser_data["os_crypt"]["encrypted_key"])

        if encrypted_key.startswith(Chromium.CHROME_DPAPI_PREFIX): 
            # Decrypt the key using Windows encryption
            # This will not work if the user's password was changed by an
            # administrator. 
            chromekey = win32crypt.CryptUnprotectData(encrypted_key[len(Chromium.CHROME_DPAPI_PREFIX):])[1]
        else:
            chromekey = encrypted_key

        # Just in case we might want this key later.. lets save it.
        # Only time wecan get it is now if it was encrypted with DPAPI
        return chromekey

    def __decrypt_ciphertext(self, ciphertext, key = self.key ) -> str:
        """decrypt data that has previously been encrypted by the selected browser."""
        
        if not (type(ciphertext) is bytes):
            ciphertext = bytes(ciphertext.encode("UTF-8"))

        # If this is a Chrome v10 encrypted password
        if ciphertext.startswith(Chromium.CHROME_ENC_VER10_PREFIX) or \
            ciphertext.startswith(Chromium.CHROME_ENC_VER10_PREFIX16) :

            # Strip the version prefix
            ciphertext = ciphertext[len(Chromium.CHROME_ENC_VER10_PREFIX):]
            nonce = ciphertext[:Chromium.CHROME_NONCE_LENGTH]
            # Strip the nonce and ver prefix
            ciphertext = ciphertext[Chromium.CHROME_NONCE_LENGTH:]
            # I hate magic numbers, but there is 16 extra bytes
            # on the end of the ciphertext. I thought this had something to do
            # with "initialization vector" or "mac len", but it doesn't.
            # Hopefully someone more crypto savvy can enlighten me.
            ciphertext = ciphertext[:-16]
            
            cipher = AES.new(self.key,AES.MODE_GCM,nonce=nonce)
            plaintext = str(cipher.decrypt(ciphertext))
        
        # Older versions of Chrome on windows did not use an internally generated
        # key, they just called DPAPI. DPAPI uses its own prefix to identify things it 
        # has encrypted, so we can look for that.
        elif ciphertext.startswith(Chromium.DPAPI_PREFIX):
            # Decrypt the key using Windows encryption
            # This will not work if the user's password was changed by an
            # administrator. 
            plaintext = win32crypt.CryptUnprotectData(ciphertext[len(Chromium.DPAPI_PREFIX):])[1].decode("UTF-8")

        return plaintext


    def get_bookmarks(self, profile : str) -> dict:
        """
        Function to get all the bookmarks of a Chromium browser.
        """
        if profile not in self.profiles_name:
            raise ValueError("Profile not found")
        with open(os.path.join(self.path, profile, "Bookmarks"), "r") as f:
            bookmarks = json.load(f)
        return bookmarks


    def get_passwords(self, profile : str) -> dict:
        """
        Function to get all the passwords of a Chromium browser.
        """
        passwords = {}
        if profile not in self.profiles_name:
            raise ValueError("Profile not found")
        db = sqlite3.connect(os.path.join(self.path, profile, "Login Data"))

        cursor = db.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        data = cursor.fetchall()

        for url, username, ciphertext in data:
            plaintext = self.__decrypt_ciphertext(ciphertext)
            if plaintext:
                passwords[url] = (url, username, plaintext)

        return passwords

    def get_cookies(self, profile : str, key = self.key, path = None) -> dict:
        """
        Function to get all the cookies of a Chromium browser.
        """
        cookies = {}

        try:
            if Path is not None:
                db = sqlite3.connect(os.path.join(self.path, profile, "Network\\Cookies"))
            if Path is None:
                db = sqlite3.connect(path)
        except:
            print(" [-] Unable to open Cookie file; expected a SQLite3 database.")
            return None
            
        db.text_factory = lambda b: b.decode(errors = 'ignore')
        cursor = db.cursor()
        cursor.execute("SELECT creation_utc, host_key, name, value, path, encrypted_value FROM cookies")
        data = cursor.fetchall()

        for cutc, host_key, name, value, path, ciphertext in data:
            plaintext = self.__decrypt_ciphertext(key, ciphertext)
            if plaintext:
                cookies["%s/%s" % (cutc,host_key)] = (host_key, name, value, path, plaintext)
            else:
                cookies["%s/%s" % (cutc,host_key)] = (host_key, name, value, path, ciphertext)

        return cookies
    
    def get_history(self, profile : str, key = self.key, Path = None) -> dict:
        """
        Function to get all the history of a Chromium browser.
        """
        history = {}
        if profile not in self.profiles_name:
            raise ValueError("Profile not found")
        if Path is None:
            db = sqlite3.connect(os.path.join(self.path, profile, "History"))
        else:
            db = sqlite3.connect(Path)
        cursor = db.cursor()
        cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
        data = cursor.fetchall()

        for url, title, visit_count, last_visit_time in data:
            history[url] = (url, title, visit_count, last_visit_time)

        return history
if __name__ == "__main__":
    a = Chromium(find_chromium_browsers()[[*find_chromium_browsers().keys()][0]])
    print(a.key)
    print(a.key)
    print()
    print(a.get_history("Default"))