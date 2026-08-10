from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64

KEY = bytes([180, 63, 132, 209, 16, 180, 233, 145])
IV = bytes([1, 216, 174, 230, 73, 173, 146, 39])

password_encrypted = "66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby"
ciphertext = base64.b64decode(password_encrypted)
cipher = DES.new(KEY, DES.MODE_CBC, IV)
plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
print(f"Password: {plaintext.decode('utf-8')}")
