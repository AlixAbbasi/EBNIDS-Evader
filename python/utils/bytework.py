#!/usr/bin/python

"""
Basic byte manipulation functions
"""

from utils.rand import rand_bytes

def align_bytes(bytes, alignment, badchars = ""):
	padding = ""
	n = len(bytes)
	
	if(n % alignment != 0):
		if(n < alignment):
			padding = rand_bytes(alignment - n, badchars)
		else:
			padding = rand_bytes(alignment - (n % alignment), badchars)
	return bytes + padding

def bytes_to_asm(bytes):
	listing = ""
	for b in bytes:
		listing += "\t.byte 0x{:02x}\n".format(ord(b))
	return listing

def bytes_to_nasm(bytes):
	listing = "shellcode: db "
	for b in bytes:
		listing += "0x{:02x}, ".format(ord(b))
	return listing + "0x00"

def bytes_to_c(bytes):
	return "unsigned char* shellcode = \"" + "".join(["\\x{:02X}".format(ord(b)) for b in bytes]) + "\""

def bytes_to_python(bytes):
	return "shellcode = \"" + "".join(["\\x{:02X}".format(ord(b)) for b in bytes]) + "\""

def bytes_to_hex(bytes):
	return bytes.encode('hex')

def translate_bytes(bytes, outformat):
	translations = {'hex': bytes_to_hex,
					'asm': bytes_to_nasm,
					'c': bytes_to_c,
					'python': bytes_to_python}
	return translations[outformat](bytes)

def contains_badchars(buf, badchars):
	return list(set(buf).intersection(badchars))
