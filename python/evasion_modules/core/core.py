#!/usr/bin/python

"""
evasion core template, methods can be overridden to implement specific functionality
"""

from struct import unpack, pack
from assembler.assembler import assembler
from arch.core import byte_packs
from evasion_modules.core.getpc import getpc_stub_builder

class evasion_module:
	def __init__(self, arch, bits, badchars = ""):
		self.arch = arch
		self.bits = bits
		self.badchars = badchars
		return

	# Routines to make encoded payload, keyfiller and decoder stubs accessible to evader
	def set_encoded_payload(self, encoded_payload):
		self.encoded_payload = encoded_payload
		return

	def set_keyfiller_stub(self, keyfiller_stub):
		self.keyfiller_stub = keyfiller_stub
		return

	def set_decoder_stub(self, decoder_stub):
		self.decoder_stub = decoder_stub

	# Set additional params
	def set_additional_params(self, additional_params):
		self.additional_params = additional_params
		return

	# getter to indicate whether this evader has a custom layer encoder
	def has_layer_encoder(self):
		return False

	# getpc stub
	def getpc_stub(self, getpc_reg):
		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		return stub_builder.basic_getpc_stub(getpc_reg)

	# generate stub to fill key registry with key value
	def keyfiller_stub(self, key_reg, key):
		if not(len(key) in byte_packs):
			raise Exception("[-]keyfiller_stub: invalid keysize")

		variables = {'key_reg': key_reg, 'key': unpack(byte_packs[len(key)], key)[0]}

		listing = '''
main:
	MOV {key_reg}, {key}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

	# to handle format encoding if necessary
	def encode(self, buf):
		return buf