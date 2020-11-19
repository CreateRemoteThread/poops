from Crypto.Cipher import AES #PyCryptodome

ENCRYPTED_FLAG = b'|Cg\x90&\x8c\xb6Y(\x9b\xf1\x88^\x0829'

user_input = input("Enter private key as a base 10 integer:\n")

k=int(user_input)
key = k.to_bytes(32,"big")
cipher = AES.new(key,AES.MODE_ECB)

flag = cipher.decrypt(ENCRYPTED_FLAG)

print("FLAG is:%s"%str(flag))
