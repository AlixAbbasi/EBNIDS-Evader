#!/usr/bin/python

"""
MMX-based "Faithfulness gap" anti-emulation armor
Anti-emulation armor integrating unsupported MMX instructions
"""

from random import choice
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from arch.core import stackpointer_registers, word_keywords, arch_registers

class evasion_faith_mmx(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		blacklist = []

		regs = arch_registers(self.arch, self.bits)

		reg1 = regs.random_mmx_reg(blacklist)

		blacklist += [reg1]

		reg2 = regs.random_mmx_reg(blacklist)

		# MIASM assembler doesn't support these so we add them manually
		# PXOR reg2, reg2
		pxor_instruction = "\t.byte 0x0F\n\t.byte 0xEF\n\t.byte 0x{:02x}\n".format((0xC0 + (9 * regs.mmx_reg_to_index(reg2))))

		# PADDD reg2, reg1	
		paddd_instruction = "\t.byte 0x0F\n\t.byte 0xFE\n\t.byte 0x{:02x}\n".format((0xC0 + (regs.mmx_reg_to_index(reg2) * 8) + regs.mmx_reg_to_index(reg1)))

		# MOVD getpc_reg, reg2
		movd_instruction = "\t.byte 0x0F\n\t.byte 0x7E\n\t.byte 0x{:02x}\n".format((0xC0 + (8 * regs.mmx_reg_to_index(reg2)) + regs.gp_reg_to_index(getpc_reg)))

		# TODO: handle this in a non-getpc seeding manner
		# TODO: polymorphize MMX instructions
  		# TODO: polymorphize between RET, JMP getpc_reg, etc.

  		variables = {'reg1': reg1, 'reg2': reg2, 'word_keyword': word_keyword, 'stackpointer_reg': stackpointer_reg, 'getpc_reg': getpc_reg, 'pxor_instruction': pxor_instruction, 'paddd_instruction': paddd_instruction, 'movd_instruction': movd_instruction}

		listing = '''
main:
	JMP docall
callback:
	MOVD {reg1}, {word_keyword} PTR [{stackpointer_reg}]
	{pxor_instruction}
	{paddd_instruction}
	{movd_instruction}
	RET
docall:
	CALL callback
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub