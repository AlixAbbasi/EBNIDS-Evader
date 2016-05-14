#!/usr/bin/python

"""
SSE-based "Faithfulness gap" anti-emulation armor
Anti-emulation armor integrating unsupported SSE instructions
"""

from random import choice
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from arch.core import stackpointer_registers, word_keywords, arch_registers

class evasion_faith_sse(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		regs = arch_registers(self.arch, self.bits)

		reg2 = regs.random_gp_reg(False, [getpc_reg])
		sse_reg1 = regs.random_sse_reg([])
		sse_reg2 = regs.random_sse_reg([sse_reg1])

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		# Raw instructions MIASM assembler couldn't handle
		lzcnt_instruction = "\t.byte 0xF3\n\t.byte 0x0F\n\t.byte 0xBD\n\t.byte 0x{:02x}\n".format((0xC0 + regs.gp_reg_to_index(reg2) + (8 * regs.gp_reg_to_index(getpc_reg))))

		cmovnb_instruction = "\t.byte 0x0F\n\t.byte 0x43\n\t.byte 0x{:02x}\n\t.byte 0x24\n".format((0x04 + (8 * regs.gp_reg_to_index(getpc_reg))))

		maxss_instruction = "\t.byte 0xF3\n\t.byte 0x0F\n\t.byte 0x5F\n\t.byte 0x{:02x}\n".format((0xC0 + regs.sse_reg_to_index(sse_reg1) + (8 * regs.sse_reg_to_index(sse_reg2))))

		variables = {'null_instr': null_instr, 'lzcnt_instruction': lzcnt_instruction, 'cmovnb_instruction': cmovnb_instruction, 'maxss_instruction': maxss_instruction, 'reg2': reg2, 'sse_reg1': sse_reg1, 'sse_reg2': sse_reg2, 'word_keyword': word_keyword, 'stackpointer_reg': stackpointer_reg, 'getpc_reg': getpc_reg, 'reg_size': reg_size}

		listing = '''
main:
	JMP docall
callback:
	{null_instr} {getpc_reg}, {getpc_reg}
	{null_instr} {reg2}, {reg2}

	SUB {reg2}, (-10 % {reg_size})
	{lzcnt_instruction}
	CMP {getpc_reg}, 3
	{cmovnb_instruction}
	
	PUSH {getpc_reg}

	MOVSS {sse_reg1}, {word_keyword} PTR [{stackpointer_reg}]

	POP {getpc_reg}

	MOV {word_keyword} PTR [{stackpointer_reg}], {reg2}
	PXOR {sse_reg2}, {sse_reg2}
	{maxss_instruction}
	MOVSS {word_keyword} PTR [{stackpointer_reg}], {sse_reg2}
	RET
docall:
	CALL callback
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub