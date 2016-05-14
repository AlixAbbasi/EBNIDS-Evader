#!/usr/bin/python

"""
Collection of keygenning stubs
"""

from random import choice
from struct import unpack, pack
from assembler.assembler import assembler
from arch.core import stackpointer_registers, word_keywords
from utils.bytework import align_bytes

class keygen_stub_builder:
	def __init__(self, arch, bits, badchars = ""):
		self.arch = arch
		self.bits = bits
		self.badchars = badchars
		return

	# CKPE keygen stub wrapper method
	# TODO: support more methods
	def ckpe_keygen_stub(self, key_reg, ckpe_method, params):
		methods = {'memaddress': self.ckpe_memaddress_keygen}
		return methods[ckpe_method](key_reg, params)

	# CKPE memory address method
	# TODO: support (longer, eg. 128-bit) key constructed from arithmetic over data fetched from multiple addresses
	def ckpe_memaddress_keygen(self, key_reg, params):
		word_keyword = word_keywords[self.bits]
		address = params['address']

		variables = {'key_reg': key_reg, 'word_keyword': word_keyword, 'address': address}

		listing = '''
main:
	MOV {key_reg}, {address}
	MOV {key_reg}, {word_keyword} PTR [{key_reg}]
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub