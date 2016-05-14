#!/usr/bin/python

"""
NEMU GP register detection
Anti-emulation armor integrating GP-register based NEMU detection
"""

from struct import unpack
from random import choice, shuffle
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, stackframepointer_registers, arch_registers, bit_packs

class evasion_detect_nemu_gp(evasion_module):

    #
    # getPC stub incorporating NEMU detection (based on the fact that all GP registers are initialized to the same constant)
    #
    # [+] Features:
    #       + Lightly polymorphic (randomized register subtraction & addiction order + polymorphic getPC code)
    #
    # [-] Limitations:
    #       - Technique only works when executed as the very first part of the shellcode, since it relies on NEMU GP register state immediately after initialization
    #
    # [*] Note:
    #       - This can be futher improved by polymorphizing both the way in which we check that all GP registers are equal and the way in which we incorporate the result in the decoder stub
    #
	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]

		regs = arch_registers(self.arch, self.bits)

		call_reg = regs.random_gp_reg(False, [])

		# Generate random xor order for GP registers
		gp_regs_s = regs.get_gp_regs(False) + [stackframepointer_registers[self.bits]]
		shuffle(gp_regs_s)

		reg1_s = gp_regs_s[0]
		reg2_s = gp_regs_s[1]
		reg3_s = gp_regs_s[2]
		reg4_s = gp_regs_s[3]
		reg5_s = gp_regs_s[4]
		reg6_s = gp_regs_s[5]
		reg7_s = gp_regs_s[6]

		# Build stack-based getPC code, store PC in getPCDestReg
		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		getpc_instruction = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		variables = {'stackpointer_reg': stackpointer_reg, 'call_reg': call_reg, 'getpc_instruction': getpc_instruction, 'reg1_s': reg1_s, 'reg2_s': reg2_s, 'reg3_s': reg3_s, 'reg4_s': reg4_s, 'reg5_s': reg5_s, 'reg6_s': reg6_s, 'reg7_s': reg7_s}

		listing = '''
main:
	; First XOR GP registers with eachother (all will subsequently be 0 in the case of NEMU)

	XOR {reg1_s}, {reg2_s}
	XOR {reg1_s}, {reg3_s}
	XOR {reg1_s}, {reg4_s}
	XOR {reg1_s}, {reg5_s}
	XOR {reg1_s}, {reg6_s}
	XOR {reg1_s}, {reg7_s}

	; total constant result of XOR over regs
	XOR {reg1_s}, 0x2F769097

	PUSH {getpc_instruction}

	TEST {reg1_s}, {reg1_s}
	CMOVNZ {call_reg}, {stackpointer_reg}
	CALL {call_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub