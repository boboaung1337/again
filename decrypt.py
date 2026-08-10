from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64

''' Found in SmarterMail.Standard.dll (using dnSpy)
keymap1 = { 125, 113, 232, 233, 160, 34, 123, 208 }, { 224, 222, 8, 14, 29, 138, 139, 223 });
keymap2 = { 180, 63, 132, 209, 16, 180, 233, 145 }, { 1, 216, 174, 230, 73, 173, 146, 39 });
'''

KEY = bytes([
    180, 63, 132, 209,
    16, 180, 233, 145
])

IV = bytes([
    1, 216, 174, 230,
    73, 173, 146, 39
])


def decrypt_password(password_encrypted):

    print("[*] Key:", KEY.hex())
    print("[*] IV:", IV.hex())

    ciphertext = base64.b64decode(password_encrypted)

    if len(ciphertext) % 8 != 0:
        raise ValueError(
            f"Invalid DES ciphertext length: {len(ciphertext)}"
        )

    cipher = DES.new(
        KEY,
        DES.MODE_CBC,
        IV
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        DES.block_size
    )

    return plaintext.decode("utf-8")


def main():
    password_encrypted = "66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby"
    plaintext = decrypt_password(password_encrypted)
    print(f"[+] Plaintext: {plaintext}")


if __name__ == "__main__":
    main()