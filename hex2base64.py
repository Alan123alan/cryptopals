#crypropals rule: always operate on bytes never on encoded strings 
import base64

#when trying to convert a hex string to it's bytes representation
#you need to use bytes.fromhex()
#then you can easily encode those bytes to base64 with base64.b64encode()
def hex_2_base64(hex_str:str)->bytes:
    return base64.b64encode(bytes.fromhex(hex_str))


#when trying to convert a base64 string to it's bytes representation
#you can use .encode("utf-8") or bytes(b64_str, "utf-8")
#then you can easily decode those bytes from base64 with base64.b64decode()
def base64_2_hex(base64_str:str)->bytes:
    # return base64.b64decode(base64_str.encode(encoding="utf-8"))
    return base64.b64decode(bytes(base64_str, "utf-8"))

#use .encode(encoding="utf-8") to get a readable representation of the b64 encoded encoded bytes
print(hex_2_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").decode(encoding="utf-8"))
#use .hex() to get a readable representation of the hex bytes
print(base64_2_hex("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t").hex())