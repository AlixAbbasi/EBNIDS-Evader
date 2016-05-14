#!/usr/bin/python

"""
FPU-based "Faithfulness gap" anti-emulation armor
Anti-emulation armor integrating unsupported FPU instructions
"""

from struct import unpack, pack
from random import choice
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from utils.rand import rand_bytes
from arch.core import stackpointer_registers, word_keywords, fpu_instructions

class evasion_faith_fpu(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]
		
		# Set of FPU store + pop/mov2reg instructions that can be used for the getPC stub

  		# FNSTENV [ESP - 0xC]
  		fnstenv_store = "\t.byte 0xD9\n\t.byte 0x74\n\t.byte 0x24\n\t.byte 0xF4\n"

  		# FNSAVE [ESP - 0x6C]
  		fnsave_store = "\t.byte 0xDD\n\t.byte 0x74\n\t.byte 0x24\n\t.byte 0x94\n"

  		# TODO: add more variations
  		fpu_saves = []

  		fpu_saves += [fnstenv_store + "\tMOV {getpc_reg}, {word_keyword} PTR [{stackpointer_reg}]\n\tSUB {getpc_reg}, (-10 % {reg_size})\n"]

  		fpu_saves += [fnsave_store + "\tMOV {getpc_reg}, {word_keyword} PTR [{stackpointer_reg} - 0x60]\n\tSUB {getpc_reg}, (-0x0D % {reg_size})\n"]


		variables = {'getpc_reg': getpc_reg, 'stackpointer_reg': stackpointer_reg, 'reg_size': reg_size, 'word_keyword': word_keyword}

  		fpu_instruction = choice(fpu_instructions)
  		fpu_save = choice(fpu_saves).format(**variables)

  		variables = {'fpu_instruction': fpu_instruction, 'fpu_save': fpu_save}

		listing = '''
main:
	{fpu_instruction}
	{fpu_save}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub