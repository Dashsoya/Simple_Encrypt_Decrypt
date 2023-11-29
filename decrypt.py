from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from base64 import b64decode
import glob

# Read the encrypted symmetric key from file and decrypt with private key
with open("encrypted_sym_key.bin", "rb") as file_in:
    sk = RSA.import_key(open("private.pem").read())
    encrypted_sym_key = file_in.read()
    cipher_rsa = PKCS1_OAEP.new(sk)
    symKey = cipher_rsa.decrypt(encrypted_sym_key)

# Read and use same iv for decrypt
with open("iv.pem", "rb") as iv_file:
    iv = iv_file.read()
    
# glob.glob to get all encrypted files
textfiles = glob.glob("*.enc")

# For loop to read encrypted files 1 by 1, decrypt and then store them in new files
for i in range(0, len(textfiles)):
    with open(textfiles[i], 'rb') as file:
        ctext = b64decode(file.read())        
    cipher = AES.new(symKey, AES.MODE_CBC, iv)
    pt_unpadded = unpad(cipher.decrypt(ctext), AES.block_size)
    plaintext = pt_unpadded.decode('utf-8')
    print(plaintext)
    with open("decrypted_text" + str(i + 1) + ".dec", "wb") as file_out:
        file_out.write(pt_unpadded)

  
