###################################################
#                                                 #
# Project: Catherine (Module: Mercy Extension)    #
# File: mercy_ext.py                              #
#                                                 #
# Author(s): {                                    #
#   Hifumi1337 <https://github.com/Hifumi1337>    #
# }                                               #
#                                                 # 
###################################################

import base64, argparse
from cryptography.fernet import Fernet
import jwt as j

parser = argparse.ArgumentParser()
parser.add_argument('-b32', '--base32', help="Decode Base32", action='store_true', default=False, required=False)
parser.add_argument('-j', '--jwt', help="Decode JWT token", action='store_true', default=False, required=False)
parser.add_argument('-f', '--fernet', help="Decrypt Fernet encryption", action='store_true', default=False, required=False)
parser.add_argument('-s', '--set_string', help="Encoded/Encrypted string", default=None, required=True)
parser.add_argument('-k', '--key', help="Fernet key // JWT secret", default=None, required=False)
args = parser.parse_args()

VERSION = "1.4.14"

class MercyExtension:
    """
    Base32 decoding
    """
    def decode_base32(self, msg: str):
        base32_bytes = msg.encode("UTF-8")
        decoder = base64.b32decode(base32_bytes)
        print(f"\nBase32 Decoded: {decoder.decode('UTF-8')}")

    """
    JWT token decoding
    """
    def decode_jwt(self, msg: str, key):
        jwt_token = msg
        jwt_secret = key
        decoded_msg = j.decode(jwt_token, str(jwt_secret), algorithms=['HS256'])
        print(f"\nJWT Token Decoded: {decoded_msg['payload']}")

    """
    Fernet decryption
    """
    def decrypt_fernet(self, msg: str, key: str):
        private_key: str = key
        encrypted_msg: str = msg

        # Requires Fernet key for the encrypted message
        fernet = Fernet(private_key)

        decrypt_msg = fernet.decrypt(encrypted_msg)
        print(f"Fernet Decrypted: {decrypt_msg.decode('UTF-8')}")

if __name__ == '__main__':
    ME = MercyExtension()

    set_msg = args.set_string
    set_key = args.key

    if args.base32:
        ME.decode_base32(set_msg)
    elif args.jwt:
        try:
            ME.decode_jwt(set_msg, set_key)
        except j.exceptions.InvalidSignatureError:
            print("\nJWT API was unable to recognize the signature")
    elif args.fernet:
        ME.decrypt_fernet(set_msg, set_key)
    else:
        print("Unrecognized method")
        exit(0)