from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RSAEncryptor:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, plaintext: str) -> bytes:
        ciphertext = self.public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

class ECCEncryptor:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def sign(self, message: str) -> bytes:
        signature = self.private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify(self, message: str, signature: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False




#for testing
# if __name__ == "__main__":
#     print("RSA Example:")
#     rsa_encryptor = RSAEncryptor()
#     rsa_encryptor.generate_keys()
#     message = "Hello RSA!"
#     encrypted = rsa_encryptor.encrypt(message)
#     print(f"Encrypted: {encrypted}")
#     decrypted = rsa_encryptor.decrypt(encrypted)
#     print(f"Decrypted: {decrypted}")

#     print("\nECC Example:")
#     ecc_encryptor = ECCEncryptor()
#     ecc_encryptor.generate_keys()
#     message = "Hello ECC!"
#     signature = ecc_encryptor.sign(message)
#     print(f"Signature: {signature.hex()}")
#     is_valid = ecc_encryptor.verify(message, signature)
#     print(f"Signature valid? {is_valid}")
