import hashlib

def compute_hash(data, algo="SHA-256"):
    if algo == "SHA-256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif algo == "SHA-512":
        return hashlib.sha512(data.encode()).hexdigest()
    elif algo == "MD5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algo == "SHA-1":
        return hashlib.sha1(data.encode()).hexdigest()
    else:
        return "Unsupported hashing algorithm"
