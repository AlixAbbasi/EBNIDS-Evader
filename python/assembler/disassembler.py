#!/usr/bin/python

"""
Rudimentary disassembler core
"""

from miasm2.arch.x86.disasm import dis_x86_32

class disassembler:
	def __init__(self, arch, bits):
		self.arch = arch
		self.bits = bits
		return

	def disassemble(self, bytecode, offset = 0):
		listing = ""
		mdis = dis_x86_32(bytecode)
		blocs = mdis.dis_multibloc(offset)

		for bloc in blocs:
			#TODO: __str__
			#listing += bloc
			print bloc

		return listing