import secrets as s
import base64
import sys
from hashlib import sha1
import hmac

pass_streght = 8

class Totp:
    def generate_secret(self, num_of_digits):
        if num_of_digits>16:
            num_of_digits = 16
        return s.token_urlsafe(num_of_digits)

    def get_totp_url(self, secret):
        b = secret.encode("UTF-8")
        e = base64.b32encode(b)
        s1 = e.decode("UTF-8")
        return 'otpauth://totp/mfaapp?secret='+s1

    def __generatePassword(self, secret, interation, digits):
        interation_bytes = interation.to_bytes(sys.getsizeof(int()),'big')
        key = secret.encode('ASCII')
        hashed = hmac.new(key, interation_bytes, sha1)
        digest = hashed.digest()
        offset = digest[hashed.digest_size-1] & 0xf
        binary =((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | (digest[offset + 3]);
        password = binary % pow(10, digits)
        return str(password)
    
    def __getCounter(self):
        import time
        return int(time.time())/30

    

    def IsValid(self, secret, password, interationdelta):
        for i in range(1,interationdelta):
            counter =self.__getCounter()
            if self.__generatePassword(secret,counter-i,6) == password:
                return True
            if self.__generatePassword(secret,counter+i,6) == password:
                return True

        return False
            
        




t = Totp()

secret = t.generate_secret(pass_streght)
url = t.get_totp_url(secret)
password = t.GeneratePassword(secret, 1, 6)
print(t.IsValid(secret,password,2))

