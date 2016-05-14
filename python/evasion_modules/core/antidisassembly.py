#!/usr/bin/python

"""
Small collection of antidisassembly routines
"""

from random import choice
from struct import unpack, pack
from assembler.assembler import assembler
from arch.core import stackpointer_registers, word_keywords, bit_packs, arch_registers
from utils.bytework import align_bytes, bytes_to_asm
from utils.rand import rand_bytes

class antidisassembly_builder:
	def __init__(self, arch, bits, badchars = ""):
		self.arch = arch
		self.bits = bits
		self.badchars = badchars
		return

	# Opaque predicate followed by garbage bytes
	def opaque_predicate(self, garbage_count):
		# Garbage bytes
		garbage_bytes = bytes_to_asm(rand_bytes(garbage_count, self.badchars))

		# Opaque predicate construction
		regs = arch_registers(self.arch, self.bits)
		reg = regs.random_gp_reg(False, [])
		mov_val = unpack(bit_packs[self.bits], rand_bytes(self.bits / 8, self.badchars))[0]
		dst_label = 'skip_garbage'

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		# small list of example opaque predicates, to be extended in the future

		set_null_instr = '\t{null_instr} {reg}, {reg}\n'
		test_instr = '\tTEST {reg}, {reg}\n'
		mov_instr = '\tMOV {reg}, {mov_val}\n'
		cmp_instr = '\tCMP {reg}, {mov_val}\n'

		opaque_predicates =  [{'setting_sequence': [set_null_instr, test_instr], 'predicate': 'JZ', 'dst': dst_label},
							  {'setting_sequence': [mov_instr, cmp_instr], 'predicate': 'JZ', 'dst': dst_label},
							  {'setting_sequence': [test_instr], 'predicate': 'JZ', 'dst': dst_label}]

		variables = {'reg': reg, 'mov_val': mov_val, 'null_instr': null_instr}
		predicate = choice(opaque_predicates)

		listing = "main:\n"

		for s in predicate['setting_sequence']:
			listing += s.format(**variables)

		listing += predicate['predicate'] + ' ' + predicate['dst'] + "\n"
		listing += garbage_bytes + dst_label + ":\n"

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing)
		return stub

	# Code transpositioning
	def code_transposition(self, garbage_count):

		reg_size = 2**self.bits
		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]
		garbage_bytes = bytes_to_asm(rand_bytes(garbage_count, self.badchars))

		variables = {'word_keyword': word_keyword, 'stackpointer_reg': stackpointer_reg, 'reg_size': reg_size, 'garbage_bytes': garbage_bytes}

		listing = '''
main:
	JMP label_0

routine_0:
	ADD {word_keyword} PTR [{stackpointer_reg}], (label_2 - label_1)
	RET

label_0:
	CALL routine_0
label_1:
	{garbage_bytes}
label_2:
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

	# Use flow redirection to jump to the middle of an instruction
	def flow_redirection(self):
		reg_size = 2**self.bits

		regs = arch_registers(self.arch, self.bits)
		reg = regs.random_gp_reg(False, [])

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		variables = {'reg': reg, 'null_instr': null_instr}

		listing_0 = '''
main:
	{null_instr} {reg}, {reg}
'''

		asm = assembler(self.arch, self.bits)
		reset_reg_instr = asm.assemble(listing_0.format(**variables))

		# jump over garbage filler + reset instruction + jmp
		jmp_offset = len(reset_reg_instr) + (self.bits / 8) + 2

		variables = {'jmp_offset': jmp_offset}

		listing_1 = '''
main:
	JMP $+{jmp_offset}
'''

		filler_count = ((self.bits / 8) - 2)
		asm = assembler(self.arch, self.bits)
		hidden_jump = unpack(bit_packs[self.bits], asm.assemble(listing_1.format(**variables)) + rand_bytes(filler_count, self.badchars))[0]

		variables = {'reg': reg, 'hidden_jump': hidden_jump, 'reset_reg_instr': bytes_to_asm(reset_reg_instr)}

		listing_2 = '''
main:
	MOV {reg}, {hidden_jump}
	{reset_reg_instr}
'''

		asm = assembler(self.arch, self.bits)
		obfuscated_jump = asm.assemble(listing_2.format(**variables))

		hidden_offset = (self.bits / 8) + len(reset_reg_instr)

		variables = {'obfuscated_jump': bytes_to_asm(obfuscated_jump), 'hidden_offset': hidden_offset}

		listing_3 = '''
main:
	{obfuscated_jump}
jump_back:
	JMP $-{hidden_offset}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing_3.format(**variables))
		return stub