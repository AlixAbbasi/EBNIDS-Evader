#!/usr/bin/python

"""
Rudimentary assembler core
"""

from miasm2.arch.x86.arch import mn_x86
from miasm2.core import parse_asm, asmbloc
from miasm2.core import asmbloc
from elfesteem.strpatchwork import StrPatchwork

class assembler:
	def __init__(self, arch, bits):
		self.arch = arch
		self.bits = bits
		return

	def assemble(self, listing):
		blocs, symbol_pool = parse_asm.parse_txt(self.arch, self.bits, listing)

		# set main label offset
		symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)

		# resolve instructions offset
		patches = asmbloc.asm_resolve_final(self.arch, blocs[0], symbol_pool)

		stub = StrPatchwork()

		for offset in patches:
			stub[offset] = patches[offset]

		return str(stub)