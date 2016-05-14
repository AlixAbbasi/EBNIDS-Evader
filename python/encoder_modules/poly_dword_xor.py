#!/usr/bin/python

"""
Polymorphic DWORD XOR encoder

Features:
	+ Lightly polymorphic (randomized registers, multiple decoder types)

TODO:
	- Add more decoder stub types

"""

from basic_xor import basic_xor
from assembler.assembler import assembler
from random import choice
from arch.core import word_keywords, ctr_regs

class poly_dword_xor(basic_xor):
	def __init__(self, plaintext_buf):
		self.decoder_key_offset = -1
		self.block_size = 4
		self.key_size = 4
		self.plaintext_buf = plaintext_buf
		self.encoded_buf = ""
		return

	#
	# Simple XOR-based light-polymorphic decoder stub
	#
	# getpc_reg:	   registry holding PC
	# key_reg:  	   registry holding key
	# keyfiller_size:  size of keyfiller stub
	# arch: 		   architecture
	# bits: 		   32 or 64
	#
	def decoder_stub(self, getpc_reg, key_reg, keyfiller_size, arch, bits):

		if(len(self.encoded_buf) < 1):
			raise Exception("[-]decoder_stub: no encoded_buf to work with")

		# registry size
		reg_size = 2**bits

		# counter register
		ctr_reg = ctr_regs[bits]

		# word keyword
		word_keyword = word_keywords[bits]

		# no conflicts
		if((getpc_reg == ctr_reg) or (key_reg == ctr_reg) or (getpc_reg == key_reg)):
			raise Exception("[-]decoder_stub: specified invalid getpc_reg (%s) or key_reg (%s)", getpc_reg, key_reg)

		# offset
		ctr_sub_val = -(((len(self.encoded_buf) - 1) / 4) + 1)

		# null instruction
		null_ctr_instructions = ['XOR', 'SUB']
		null_ctr_instr = choice(null_ctr_instructions)

		# static for now due to miasm problems
		decoder_len = 15

		
		variables = {'word_keyword': word_keyword, 'decoder_len': decoder_len, 'block_size': self.block_size, 'getpc_reg': getpc_reg, 'key_reg': key_reg, 'ctr_reg': ctr_reg, 'ctr_sub_val': ctr_sub_val, 'null_ctr_instr': null_ctr_instr, 'reg_size': reg_size, 'keyfiller_size': keyfiller_size}

		listing = '''
main:
	SUB    {getpc_reg}, (-({decoder_len} + {keyfiller_size}) % {reg_size})

	{null_ctr_instr} {ctr_reg}, {ctr_reg}
	SUB    {ctr_reg}, ({ctr_sub_val} % {reg_size})

decoder_loop:
	XOR    {word_keyword} PTR [{getpc_reg}], {key_reg}
	SUB    {getpc_reg}, (-{block_size} % {reg_size})
	LOOP   decoder_loop
payload_body:
'''
		asm = assembler(arch, bits)
		stub = asm.assemble(listing.format(**variables))
		return stub