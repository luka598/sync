import pytest
from src import *

def test_aes_message_8_key_3_byte():
	key = b"key"
	message = b"01234567"
	aes = aesCipher(key=key)
	iv = aes.iv
	ct_message = aes.encrypt(message)
	aes = aesCipher(key=key, iv=iv)
	pt_message = aes.decrypt(ct_message)
	assert pt_message == message, "Messages not same!"

def test_aes_message_16_key_3_byte():
	key = b"key"
	message = b"0123456789012345"
	aes = aesCipher(key=key)
	iv = aes.iv
	ct_message = aes.encrypt(message)
	aes = aesCipher(key=key, iv=iv)
	pt_message = aes.decrypt(ct_message)
	assert pt_message == message, "Messages not same!"


def test_aes_message_16_key_16_byte():
	key = b"0123456789012345"
	message = b"0123456789012345"
	aes = aesCipher(key=key)
	iv = aes.iv
	ct_message = aes.encrypt(message)
	aes = aesCipher(key=key, iv=iv)
	pt_message = aes.decrypt(ct_message)
	assert pt_message == message, "Messages not same!"

def test_aes_message_16_key_32_byte():
	key = b"01234567890123456789012345678901"
	message = b"0123456789012345"
	aes = aesCipher(key=key)
	iv = aes.iv
	ct_message = aes.encrypt(message)
	aes = aesCipher(key=key, iv=iv)
	pt_message = aes.decrypt(ct_message)
	assert pt_message == message, "Messages not same!"

def test_aes_message_32_key_16_byte():
	key = b"0123456789012345"
	message = b"01234567890123456789012345678901"
	aes = aesCipher(key=key)
	iv = aes.iv
	ct_message = aes.encrypt(message)
	aes = aesCipher(key=key, iv=iv)
	pt_message = aes.decrypt(ct_message)
	assert pt_message == message, "Messages not same!"

def test_aes_message_69_key_16_byte():
	key = b"0123456789012345"
	message = b"012345678901234567890123456789010123456789012345678901234567890123456"
	aes = aesCipher(key=key)
	iv = aes.iv
	ct_message = aes.encrypt(message)
	aes = aesCipher(key=key, iv=iv)
	pt_message = aes.decrypt(ct_message)
	assert pt_message == message, "Messages not same!"

def test_aes_message_10_10_key_16_byte():
	key = b"0123456789012345"
	message = b""
	aes = aesCipher(key=key)
	iv = aes.iv
	ct_message = b""
	ct_message += aes.encrypt(b"0123456789")
	message += b"0123456789"
	ct_message += aes.encrypt(b"0123456789")
	message += b"0123456789"
	aes = aesCipher(key=key, iv=iv)
	pt_message = aes.decrypt(ct_message)
	assert pt_message == message, "Messages not same!"

def test_aes_encrypt_in_decrypt():
	key = b"123"
	message = b"123"
	aes = aesCipher(key=key)
	aes.encrypt(key)
	try:
		aes.decrypt(key)
		failed = False
	except:
		failed = True
	assert failed, "aesCipher decrypted in encrypt mode"

def test_aes_decrypt_in_encrypt():
	key = b"1234567890123456"
	iv = b"1234567890123456"
	message = b"123"
	aes = aesCipher(key=key, iv=iv)
	aes.decrypt(key)
	try:
		aes.encrypt(key)
		failed = False
	except:
		failed = True
	assert failed, "aesCipher encrypted in encrypt mode"

def test_rsi_generate_keys():
	pass

def test_rsi_export_import_private_key():
	pass

def test_rsi_export_import_public_key():
	pass

def test_rsi_encrypt_decrypt():
	pass