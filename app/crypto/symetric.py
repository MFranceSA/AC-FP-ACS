from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
import base64

def _get_key(key, algo):
    key_bytes = key.encode()
    if algo == "3DES":
        # Pad or trim to 24 bytes
        while len(key_bytes) < 24:
            key_bytes += b'0'
        key_bytes = key_bytes[:24]
        # Make sure it's a valid 3DES key
        try:
            key_bytes = DES3.adjust_key_parity(key_bytes)
        except ValueError:
            raise ValueError("Invalid 3DES key. Please use a different key.")
        return key_bytes
    if algo == "AES":
        return key.encode("utf-8").ljust(16, b"0")[:16]
    elif algo == "DES":
        return key.encode("utf-8").ljust(8, b"0")[:8]
    else:
        raise ValueError("Unsupported algorithm")

def encrypt(text, key, algo="AES"):
    key_bytes = _get_key(key, algo)
    if algo == "AES":
        cipher = AES.new(key_bytes, AES.MODE_CBC)
    elif algo == "DES":
        cipher = DES.new(key_bytes, DES.MODE_CBC)
    elif algo == "3DES":
        cipher = DES3.new(key_bytes, DES3.MODE_CBC)
    else:
        return "Unsupported algorithm"
    ct_bytes = cipher.encrypt(pad(text.encode(), cipher.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def decrypt(cipher_text, key, algo="AES"):
    key_bytes = _get_key(key, algo)
    iv, ct = cipher_text.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    if algo == "AES":
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    elif algo == "DES":
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    elif algo == "3DES":
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
    else:
        return "Unsupported algorithm"
    pt = unpad(cipher.decrypt(ct), cipher.block_size)
    return pt.decode()

def encrypt_file(data, key, algo="AES"):
    key_bytes = _get_key(key, algo)
    if algo == "AES":
        cipher = AES.new(key_bytes, AES.MODE_CBC)
    elif algo == "DES":
        cipher = DES.new(key_bytes, DES.MODE_CBC)
    elif algo == "3DES":
        cipher = DES3.new(key_bytes, DES3.MODE_CBC)
    else:
        raise ValueError("Unsupported algorithm")
    ct_bytes = cipher.encrypt(pad(data, cipher.block_size))
    return cipher.iv + ct_bytes

def decrypt_file(data, key, algo="AES"):
    key_bytes = _get_key(key, algo)
    if algo == "AES":
        iv = data[:16]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        ct = data[16:]
    elif algo == "DES":
        iv = data[:8]
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        ct = data[8:]
    elif algo == "3DES":
        iv = data[:8]
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
        ct = data[8:]
    else:
        raise ValueError("Unsupported algorithm")
    pt = unpad(cipher.decrypt(ct), cipher.block_size)
    return pt
