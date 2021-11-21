#pyright: reportMissingImports=false

import json
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def get_key(key=None):
	if key == None:
		key = get_random_bytes(16)
	else:
		key = (bytes(key)*16)[:16]
	return key

class aesCipher():
	def __init__(self, key=None, iv=None) -> None:
		key = get_key(key)
		
		if iv is None:
			self.mode = "encrypt"
		else:
			self.mode = "decrypt"

		if self.mode == "encrypt":
			self.cipher = AES.new(key, AES.MODE_CBC)
			self.iv = self.cipher.iv
		else:
			self.cipher = AES.new(key, AES.MODE_CBC, iv)
		return

	def encrypt(self, pt):
		assert self.mode == "encrypt", "Can't encrypt in decrypt mode!"
		ct = b""
		while len(pt) > 0:
			pt_block = pt[:AES.block_size]
			if len(pt_block) < AES.block_size:
				pt_block = pad(pt_block, AES.block_size)
			ct += self.cipher.encrypt(pt_block)
			pt = pt[AES.block_size:]
		return ct

	def decrypt(self, ct):
		assert self.mode == "decrypt", "Can't decrypt in encrypt mode!"
		pt = b""
		while len(ct) > 0:
			ct_block = ct[:AES.block_size]
			pt_block = self.cipher.decrypt(ct_block)
			try:
				pt += unpad(pt_block, AES.block_size)
			except ValueError:
				pt += pt_block
			ct = ct[AES.block_size:]
		return pt

class rsaKeys():
	def __init__(self) -> None:
		self.private_key = None
		self.public_key = None
		return

	def generate_keys(self, keysize=4096):
		self.private_key = RSA.generate(keysize)
		self.generate_public_key()
		return

	def generate_public_key(self):
		self.public_key = self.private_key.publickey()

	def export_private_key(self, password):
		private_key = self.private_key.export_key(format="DER")
		aes = aesCipher(key=password)
		ct_private_key = aes.encrypt(private_key)
		exported_private_key = aes.iv + ct_private_key
		return exported_private_key

	def export_private_key_file(self, password):
		with open("private_key.bin", "wb") as f:
			f.write(self.export_private_key(password))
		return

	def import_private_key(self, password, exported_key):
		iv = exported_key[:16]
		ct_private_key = exported_key[16:]
		aes = aesCipher(key=password, iv=iv)
		private_key = aes.decrypt(ct_private_key)
		self.private_key = RSA.import_key(private_key)

	def import_private_key_file(self, password):
		with open("private_key.bin", "rb") as f:
			exported_key = f.read()
		self.import_private_key(password, exported_key)
		return

	def export_public_key(self):
		public_key = self.public_key.export_key(format="DER")
		return public_key

	def export_public_key_file(self):
		with open("public_key.bin", "wb") as f:
			f.write(self.export_public_key())

	def import_public_key(self, public_key_bin):
		self.public_key = RSA.import_key(public_key_bin)

	def import_public_key_file(self):
		with open("public_key.bin", "wb") as f:
			public_key_bin = f.read()
		self.import_public_key(public_key_bin)

	def encrypt(self, pt, public_key=None):
		if public_key is None:
			assert self.public_key is not None, "Can't encrypt without public key"
			public_key == self.public_key
		cipher_rsa = PKCS1_OAEP.new(public_key)
		ct = cipher_rsa.encrypt(pt)
		return ct

	def decrypt(self, ct, private_key=None):
		if private_key is None:
			assert self.public_key is not None, "Can't decrypt without private key"
			private_key = self.private_key
		cipher_rsa = PKCS1_OAEP.new(private_key)
		pt = cipher_rsa.decrypt(ct)
		return pt