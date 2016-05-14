#!/usr/bin/python

"""
Plain evader, doesn't evade anything simply serves as encoder
"""

from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from utils.bytework import bytes_to_asm

class evasion_plain(evasion_module):

	def getpc_stub(self, getpc_reg):
		variables = {'getpc_reg': getpc_reg}
		listing = '''
main:
	POP {getpc_reg}
	JMP {getpc_reg}
'''

		asm = assembler(self.arch, self.bits)
		popjmp = asm.assemble(listing.format(**variables))

		variables = {'popjmp': bytes_to_asm(popjmp)}

		listing = '''
main:
	JMP do_callback
callback:
	{popjmp}
do_callback:
	CALL callback
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub