from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt(text, key, algo="AES"):
    if algo != "AES":
        return "Only AES supported for now"
    key = key.encode("utf-8").ljust(16, b"0")[:16]
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def decrypt(cipher_text, key, algo="AES"):
    if algo != "AES":
        return "Only AES supported for now"
    key = key.encode("utf-8").ljust(16, b"0")[:16]
    iv, ct = cipher_text.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()
