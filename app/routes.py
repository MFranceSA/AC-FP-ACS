from flask import Flask, render_template, request, send_file, redirect, url_for, flash, get_flashed_messages
import os
from werkzeug.utils import secure_filename
from .crypto import symetric, hashing, crypto_asymmetric
from .crypto import hashing as hashing_module
import io

app = Flask(__name__)
app.secret_key = "supersecretkey"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/symmetric", methods=["GET", "POST"])
def symmetric():
    encrypt_result = None
    decrypt_result = None
    encrypt_file_result = None
    decrypt_file_result = None
    text_error = None
    file_error = None
    algorithm = request.args.get("algorithm", "AES")

    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "encrypt":
                text = request.form.get("plain_text", "").strip()
                key = request.form.get("key", "").strip()
                if not text or not key:
                    text_error = "Both text and key are required for encryption."
                else:
                    output = symetric.encrypt(text, key, algorithm)
                    encrypt_result = {"input": text, "output": output}
            elif action == "decrypt":
                cipher_text = request.form.get("cipher_text", "").strip()
                key = request.form.get("key", "").strip()
                if not cipher_text or not key:
                    text_error = "Both ciphertext and key are required for decryption."
                else:
                    try:
                        output = symetric.decrypt(cipher_text, key, algorithm)
                        decrypt_result = {"input": cipher_text, "output": output}
                    except Exception as e:
                        text_error = "Decryption failed: The key is incorrect or the ciphertext is corrupted."
            elif action == "encrypt_file":
                file = request.files.get("file")
                key = request.form.get("key", "").strip()
                if not file or not key:
                    file_error = "Both file and key are required for file encryption."
                else:
                    filename = file.filename
                    if filename.lower().endswith(".txt"):
                        text = file.read().decode(errors="ignore")
                        output = symetric.encrypt(text, key, algorithm)
                        mem = io.BytesIO()
                        mem.write(output.encode())
                        mem.seek(0)
                        return send_file(
                            mem,
                            as_attachment=True,
                            download_name=filename.rsplit(".", 1)[0] + ".enc.txt",
                            mimetype="text/plain"
                        )
                    else:
                        data = file.read()
                        output = symetric.encrypt_file(data, key, algorithm)
                        mem = io.BytesIO()
                        mem.write(output)
                        mem.seek(0)
                        ext = filename.split('.')[-1] if '.' in filename else ''
                        outname = filename + ".enc" if ext else filename + ".enc"
                        return send_file(
                            mem,
                            as_attachment=True,
                            download_name=outname,
                            mimetype="application/octet-stream"
                        )
            elif action == "decrypt_file":
                file = request.files.get("file")
                key = request.form.get("key", "").strip()
                if not file or not key:
                    file_error = "Both file and key are required for file decryption."
                else:
                    filename = file.filename
                    if filename.lower().endswith(".txt"):
                        cipher_text = file.read().decode(errors="ignore")
                        try:
                            output = symetric.decrypt(cipher_text, key, algorithm)
                            mem = io.BytesIO()
                            mem.write(output.encode())
                            mem.seek(0)
                            return send_file(
                                mem,
                                as_attachment=True,
                                download_name=filename.rsplit(".", 1)[0] + ".dec.txt",
                                mimetype="text/plain"
                            )
                        except Exception:
                            file_error = "Unable to provide the file: The key is incorrect or the ciphertext is corrupted."
                    else:
                        data = file.read()
                        try:
                            output = symetric.decrypt_file(data, key, algorithm)
                            mem = io.BytesIO()
                            mem.write(output)
                            mem.seek(0)
                            ext = filename.split('.')[-1] if '.' in filename else ''
                            outname = filename + ".dec" if ext else filename + ".dec"
                            return send_file(
                                mem,
                                as_attachment=True,
                                download_name=outname,
                                mimetype="application/octet-stream"
                            )
                        except Exception:
                            file_error = "Unable to provide the file: The key is incorrect or the file is corrupted."
        except Exception as e:
            # Catch any error (like 3DES key error) and flash it
            return redirect(url_for("symmetric", algorithm=algorithm))

    return render_template(
        "symmetric.html",
        algorithm=algorithm,
        encrypt_result=encrypt_result,
        decrypt_result=decrypt_result,
        encrypt_file_result=encrypt_file_result,
        decrypt_file_result=decrypt_file_result,
        text_error=text_error,
        file_error=file_error
    )

@app.route("/asymmetric", methods=["GET", "POST"])
def asymmetric():
    encrypt_rsa_result = None
    decrypt_rsa_result = None
    sign_ecc_result = None
    verify_ecc_result = None
    decrypt_rsa_error = None
    verify_ecc_error = None
    algorithm = request.args.get("algorithm", "RSA")

    if request.method == "POST":
        action = request.form.get("action")
        if action == "encrypt_rsa":
            text = request.form.get("plain_text")
            output = rsa.encrypt(text)
            encrypt_rsa_result = {"input": text, "output": output.hex()}
        elif action == "decrypt_rsa":
            cipher_text = request.form.get("cipher_text")
            try:
                output = rsa.decrypt(bytes.fromhex(cipher_text))
                decrypt_rsa_result = {"input": cipher_text, "output": output}
            except Exception:
                decrypt_rsa_error = "Decryption failed: The key is incorrect or the ciphertext is corrupted."
        elif action == "sign_ecc":
            text = request.form.get("plain_text")
            output = ecc.sign(text)
            sign_ecc_result = {"input": text, "output": output.hex()}
        elif action == "verify_ecc":
            text = request.form.get("plain_text")
            signature = request.form.get("signature")
            try:
                valid = ecc.verify(text, bytes.fromhex(signature))
                verify_ecc_result = {"input": text, "output": str(valid)}
            except Exception:
                verify_ecc_error = "Verification failed: The signature or input is invalid."

    return render_template(
        "asymmetric.html",
        algorithm=algorithm,
        encrypt_rsa_result=encrypt_rsa_result,
        decrypt_rsa_result=decrypt_rsa_result,
        sign_ecc_result=sign_ecc_result,
        verify_ecc_result=verify_ecc_result,
        decrypt_rsa_error=decrypt_rsa_error,
        verify_ecc_error=verify_ecc_error
    )

@app.route("/hashing", methods=["GET", "POST"])
def hashing_view():
    hash_text_result = None
    hash_file_result = None
    algorithm = request.args.get("algorithm", "SHA-256")  # Default to SHA-256

    if request.method == "POST":
        if request.form.get("action") == "hash_text":
            text = request.form.get("plain_text")
            output = hashing.compute_hash(text, algorithm)
            hash_text_result = {"input": text, "output": output}
        elif request.form.get("action") == "hash_file":
            file = request.files["file"]
            filename = file.filename
            data = file.read().decode(errors="ignore")
            output = hashing.compute_hash(data, algorithm)
            if filename.lower().endswith(".txt"):
                # Return a downloadable .txt file with the hash
                mem = io.BytesIO()
                mem.write(output.encode())
                mem.seek(0)
                return send_file(
                    mem,
                    as_attachment=True,
                    download_name=filename.rsplit(".", 1)[0] + f".{algorithm.lower()}.hash.txt",
                    mimetype="text/plain"
                )
            else:
                # Show hash in the UI as before
                hash_file_result = {"input": file.filename, "output": output}

    return render_template(
        "hashing.html",
        algorithm=algorithm,
        hash_text_result=hash_text_result,
        hash_file_result=hash_file_result
    )

@app.route("/algoinfo")
def algoinfo():
    return render_template("algoinfo.html")

# --- SYMMETRIC ENCRYPTION ---
@app.route("/encrypt_symmetric", methods=["POST"])
def encrypt_symmetric():
    text = request.form.get("plain_text")
    key = request.form.get("key")
    algo = request.form.get("algorithm")
    result = symetric.encrypt(text, key, algo)
    flash(f"Encrypted: {result}", "info")
    return redirect(url_for("symmetric"))

@app.route("/decrypt_symmetric", methods=["POST"])
def decrypt_symmetric():
    cipher_text = request.form.get("cipher_text")
    key = request.form.get("key")
    algo = request.form.get("algorithm")
    result = symetric.decrypt(cipher_text, key, algo)
    flash(f"Decrypted: {result}", "info")
    return redirect(url_for("symmetric"))

@app.route("/encrypt_symmetric_file", methods=["POST"])
def encrypt_symmetric_file():
    file = request.files["file"]
    key = request.form.get("key")
    algo = request.form.get("algorithm")
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    with open(filepath, "rb") as f:
        data = f.read()
    result = symetric.encrypt_file(data, key, algo)
    outpath = filepath + ".enc"
    with open(outpath, "wb") as f:
        f.write(result)
    return send_file(outpath, as_attachment=True)

@app.route("/decrypt_symmetric_file", methods=["POST"])
def decrypt_symmetric_file():
    file = request.files["file"]
    key = request.form.get("key")
    algo = request.form.get("algorithm")
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    with open(filepath, "rb") as f:
        data = f.read()
    result = symetric.decrypt_file(data, key, algo)
    outpath = filepath + ".dec"
    with open(outpath, "wb") as f:
        f.write(result)
    return send_file(outpath, as_attachment=True)

# --- ASYMMETRIC ENCRYPTION ---
rsa = crypto_asymmetric.RSAEncryptor()
ecc = crypto_asymmetric.ECCEncryptor()
rsa.generate_keys()
ecc.generate_keys()

@app.route("/encrypt_rsa", methods=["POST"])
def encrypt_rsa():
    text = request.form.get("plain_text")
    ciphertext = rsa.encrypt(text)
    flash(f"RSA Encrypted (base64): {ciphertext.hex()}", "info")
    return redirect(url_for("asymmetric"))

@app.route("/decrypt_rsa", methods=["POST"])
def decrypt_rsa():
    ciphertext = bytes.fromhex(request.form.get("cipher_text"))
    plaintext = rsa.decrypt(ciphertext)
    flash(f"RSA Decrypted: {plaintext}", "info")
    return redirect(url_for("asymmetric"))

@app.route("/sign_ecc", methods=["POST"])
def sign_ecc():
    text = request.form.get("plain_text")
    signature = ecc.sign(text)
    flash(f"ECC Signature (hex): {signature.hex()}", "info")
    return redirect(url_for("asymmetric"))

@app.route("/verify_ecc", methods=["POST"])
def verify_ecc():
    text = request.form.get("plain_text")
    signature = bytes.fromhex(request.form.get("signature"))
    valid = ecc.verify(text, signature)
    flash(f"ECC Signature valid? {valid}", "info")
    return redirect(url_for("asymmetric"))

# --- HASHING ---
@app.route("/hash_text", methods=["POST"])
def hash_text():
    text = request.form.get("plain_text")
    algo = request.form.get("algorithm")
    result = hashing.compute_hash(text, algo)
    flash(f"Hash: {result}", "info")
    return redirect(url_for("hashing_view"))

@app.route("/hash_file", methods=["POST"])
def hash_file():
    file = request.files["file"]
    algo = request.form.get("algorithm")
    data = file.read()
    result = hashing.compute_hash(data.decode(errors="ignore"), algo)
    flash(f"File Hash: {result}", "info")
    return redirect(url_for("hashing_view"))