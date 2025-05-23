# AppliedCryptograpy-FinalProject-AquilinoCasilaSanAndres

# CryptoSuite: Applied Cryptography Project
### CSAC 329 – Applied Cryptography
**Date:** May 2025

---

## 👥 Group Members
- Eugene Aquilino – AES, GUI Design
- John Michael Casila – RSA, Hashing
- Mary France San Andres – Documentation, File Support
- ...

---

## 📖 Introduction
> This application demonstrates cryptographic principles through a user-friendly interface supporting text and file encryption/decryption and hashing. The core purpose is to secure communication, data, and information exchange. It showcases the importance of data confidentiality, integrity, and authenticity in modern computing.
---

## Project Objectives
>  To implement a minimum of three symmetric encryption algorithms capable of handling both text and file encryption/decryption.
> To implement at least two asymmetric encryption algorithms for text encryption/decryption.
> To incorporate a minimum of four distinct hashing functions for generating hashes of both text and files.
> To develop a user interface (UI) based application for easy interaction with the cryptographic functionalities.
> To provide accessible information and descriptions for each implemented cryptographic algorithm directly within the application and its documentation.

## Discussions:

### Overall Application Architecture and UI Choice:
>The UI choice for this application is simple, easy to use and very functional. The side part navigation on the left is easy to access to the various cryptographic categories includes home, symmetric encryption, asymmetric encryption, hashing and algorithm info. The right main content changes according to the selected category allows users to switch between different algorithms. The input fields for text and file operations are clearly labeled and grouped with distinct "Encrypt" and "Decrypt" or "Hash" buttons. The overall aesthetic uses a high-contrast blue and white color scheme, ensuring readability and a professional appearance. 

### Implemented Cryptographic Algorithms:

***Name and Type:*** AES - Advanced Encryption Standard (Symmetric Encryption)

>***Background:*** It is developed by the National Institute of Standards and Technology (NIST) in 2001 [1].

>***Description:*** AES is a symmetric block cipher that operates on fixed-size blocks of data (128 bits) and uses keys of 128, 192, or 256 bits. It iteratively applies rounds of substitution and permutation operations[1].

>***Libraries used:*** Crypto Cipher import AES, Crypto Util Padding import pad, unpad and base64.

>***Integrated:*** This algorithm will be used to encrypt and decrypt both text input and files, as per project requirements for symmetric algorithms. Users will be able to select AES, input text or a file, provide a key, and perform encryption or decryption.

***Name and Type:*** DES - Data Encryption Standard(Symmetric Encryption)

>***Background:*** DES was developed by IBM in the late 1960s and adopted by the U.S. government in 1977 as an official Federal Information Processing Standard (FIPS)[2].

>***Description:*** DES is a 64 bit block cipher which means that it encrypts data 64 bits at a time. This is contrasted to a stream cipher in which only one bit at a time (or sometimes small groups of bits such as a byte) is encrypted[2].

>***Libraries used:*** Crypto Cipher import DES, Crypto.Util.Padding import pad, unpad and base64.

>***Integrated:*** DES will be implemented to support text and file encryption/decryption. Users can select DES, input their data or file, provide a key, and choose to encrypt or decrypt.

***Name and Type:*** 3DES - Triple Data Encryption Standard (Symmetric Encryption)
>***Background:*** The Triple-DES scheme was introduced in 1978.[3]

>***Description:*** Triple Data Encryption Standard (Triple DES or 3DES) is a symmetric block cipher-based cryptography standard that uses fixed length keys with three passes of the DES algorithm.It uses three DES iterations as the encryption and decryption process. This scheme uses a 168-bit key, offers improved security — but is slower than the standard DES implementation. [3]

>***Libraries used:*** Crypto Cipher import DES3, Crypto.Util.Padding import pad, unpad and base64.

>***Integrated:***3DES will be offered as another symmetric encryption option for both text and files, enhancing security over standard DES.

***Name and Type:*** RSA - Rivest-Shamir-Adleman (Asymmetric Encryption)

>***Background:*** RSA was named after its inventors Ron Rivest, Adi Shamir, and Leonard Adleman. It was introduced in 1977. Ut was the first of its kind to be able to serve both purposes of encrypting data for confidentiality and creating digital signatures for integrity and non-repudiation.[4]

>***Description:*** RSA is founded on the concept of number theory and relies the computational difficulty of factoring large prime numbers. In the RSA encryption process, the public key is used to encrypt the plaintext data into an unreadable ciphertext. This public key encryption is designed so that only the corresponding private key from the RSA key pair can decrypt the ciphertext back into the original plaintext[4].

>***Libraries used:*** Cyptography hazmat primitives asymmetric import ec, serialization, hashes and padding.

>***Integrated:*** RSA will be used for text encryption/decryption. The application will likely manage key generation (public/private pair) and allow users to encrypt text with a public key and decrypt with the corresponding private key.

***Name and Type:*** ECC (Asymmetric Encryption)

>***Background:*** ECC was proposed by Neal Koblitz and Victor S. Miller in 1985. It offers equivalent security to RSA with smaller key sizes, making it more efficient for resource-constrained devices [6].

>***Description:*** ECC is an asymmetric cryptographic approach based on the algebraic structure of elliptic curves over finite fields. The security of ECC relies on the difficulty of solving the Elliptic Curve Discrete Logarithm Problem (ECDLP)[5].

>***Libraries used:*** Cyptography hazmat primitives asymmetric import rsa, serialization, hashes and padding.

>***Integrated:*** ECC will be implemented as an alternative asymmetric algorithm for text encryption/decryption, providing comparable security to RSA with potentially better performance due to smaller key sizes.

***Name and Type:*** SHA-256 (Hashing)

>***Background:*** SHA 256 is a part of the SHA 2 family of algorithms, where SHA stands for Secure Hash Algorithm. Published in 2001, it was a joint effort between the NSA and NIST to introduce a successor to the SHA 1 family, which was slowly losing strength against brute force attacks[7].

>***Description:*** SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It processes input data in 512-bit (64-byte) blocks. The algorithm involves a series of rounds that mix and transform the data using bitwise operations, modular additions, and predefined constants. It's designed to be one-way and collision-resistant[7].

>***Libraries used:*** Hashlib

>***Integrated:*** SHA-256 will be used to generate hash values for both text input and files, allowing users to verify data integrity.

***Name and Type:*** SHA-512 (Hashing)

>***Background:*** It is part of the SHA-2 family, which was designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST) in 2001[8].

>***Description:*** SHA-512 (Secure Hash Algorithm 512) is a cryptographic hash function that produces a fixed-size 512-bit (64-byte) hash value from input data of any size[8].

>***Libraries used:*** Hashlib

>***Integrated:*** SHA-512 will provide another hashing option for text and files, offering a higher level of collision resistance due to its larger hash size.

***Name and Type:*** MD5 (Hashing)

>***Background:*** MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. It was designed by Ronald Rivest in 1991[10].

>***Description:*** MD5 runs entire files through a mathematical hashing algorithm to generate a signature that can be matched with an original file. It converts data into a string of 32 characters[9].

>***Libraries used:*** Hashlib

>***Integrated:*** MD5 will be included as a hashing option for text and files. It's important to note its vulnerabilities and recommend its use primarily for checksum purposes rather than security-critical applications. This information should be accessible within the application.

***Name and Type:*** BLAKE2 (Hashing)

>***Background:*** Blakse2 is a cryptographic hash function based on BLAKE, it is created by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. It was announced on December 21, 2012[11].

>***Description:*** BLAKE2 (the one checksum currently uses) computes a message digest that is 256 bits long, and represented as a 64-character hexadecimal number[12].

>***Libraries used:*** Hashlib

>***Integrated:*** BLAKE2 will be offered as a modern, fast, and secure hashing option for both text and files.

## References

>[1] GeeksforGeeks. 2021. Advanced Encryption Standard (AES). GeeksforGeeks. Retrieved May 22, 2025 from https://www.geeksforgeeks.org/advanced-encryption-standard-aes/.

>[2]2025. HISTORY OF DES. Umsl.edu. Retrieved May 22, 2025  from https://www.umsl.edu/~siegelj/information_theory/projects/des.netau.net/des%20history.html#:~:text=DES%20was%20the%20result%20of,of%20significant%20changes%20were%20introduced.

>[3] Muhammad Raza. 2025. The Triple DES Intro: Triple Data Encryption Standard | Splunk. Splunk. Retrieved May 22, 2025 from https://www.splunk.com/en_us/blog/learn/triple-des-data-encryption-standard.html

>[4] Amanda Tucker. 2024. What is RSA Asymmetric Encryption? How Does it Work? SecureW2. Retrieved May 22, 2025 from https://www.securew2.com/blog/what-is-rsa-asymmetric-encryption

>[5] Annie Badman and Matt Kosinski. 2024. Asymmetric encryption. Ibm.com. Retrieved May 22, 2025 from https://www.ibm.com/think/topics/asymmetric-encryption
‌
>‌[6] Rahul Awati and Andrew Froehlich. 2025. What is elliptical curve cryptography (ECC)? Search Security. Retrieved May 22, 2025 from https://www.techtarget.com/searchsecurity/definition/elliptical-curve-cryptography

>[7] Baivab Kumar Jena. 2021. A Definitive Guide to Learn The  SHA-256 (Secure Hash Algorithms). Simplilearn.com. Retrieved May 22, 2025 from https://www.simplilearn.com/tutorials/cyber-security-tutorial/sha-256-algorithm
‌
>[8] 2019. What is the SHA 512 algorithm? Quora. Retrieved May 22, 2025 from https://www.quora.com/What-is-the-SHA-512-algorithm

> [9] Anthony Freda. 2022. What Is the MD5 Hashing Algorithm and How Does It Work? What Is the MD5 Hashing Algorithm and How Does It Work? Retrieved May 22, 2025 from https://www.avast.com/c-md5-hashing-algorithm

>[10] Contributors to. 2001. message-digest hashing algorithm. Wikipedia.org. Retrieved May 22, 2025 from https://en.wikipedia.org/wiki/MD5
‌
‌>[11] Contributors to. 2010. Wikipedia article covering the BLAKE series of cryptographic hash functions. Wikipedia.org. Retrieved May 22, 2025 from https://en.wikipedia.org/wiki/BLAKE_(hash_function)

>[12] Sooryan. 2025. A quick summary of blake2, a cryptographic hash function. Gist. Retrieved May 22, 2025 from https://gist.github.com/sooryan/8d1b2c19bf0b971c11366b0680908d4b
