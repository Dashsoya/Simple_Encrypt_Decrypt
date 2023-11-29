from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from base64 import b64encode
import glob

# Generate random symmetric key
symKey = get_random_bytes(16)

# Generate random private and public keys and store them in files
key = RSA.generate(2048)
private_key = key.export_key()
with open("private.pem", "wb") as file_out:
    file_out.write(private_key)

public_key = key.publickey().export_key()
with open("receiver.pem", "wb") as file_out:
    file_out.write(public_key)

# Hardcoded iv
iv = b'randomiv87654321'

# glob.glob to get all .txt files in the same folder
textfiles = glob.glob("*.txt")

# Loop through all .txt files 1 by 1, read, encrypt and store in new file.
for i in range(0, len(textfiles)):
    cipher = AES.new(symKey, AES.MODE_CBC, iv)
    with open(textfiles[i], 'rb') as file:
        original = file.read()
        ct_bytes = cipher.encrypt(pad(original, AES.block_size))
        with open("encrypted_text" + str(i + 1) + ".enc", "wb") as file_out:
            file_out.write(b64encode(ct_bytes))
            
# Write IV to file because must be same for decryption
with open("iv.pem", "wb") as file_out:
    file_out.write(iv)

# Encrypt the symmetric key (symKey) with the recipient's public key and store it in a file
pk = RSA.import_key(open("receiver.pem").read())
cipher_rsa = PKCS1_OAEP.new(pk)
encrypted_sym_key = cipher_rsa.encrypt(symKey)
with open("encrypted_sym_key.bin", "wb") as file_out:
    file_out.write(encrypted_sym_key)
