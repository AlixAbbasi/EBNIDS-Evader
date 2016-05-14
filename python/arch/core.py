#!/usr/bin/python

"""
Basic CPU architecture operations core

Only supports x86 for now

8-bit low registers are mapped as 8 | 0, high registers as 8 | 1
"""

from miasm2.arch.x86.arch import mn_x86
from random import choice

# Architectures
architectures = {'x86': mn_x86}

# GP registers without stack-related regs
regs08_low_lst = ["AL", "CL", "DL", "BL"]
regs08_high_lst = ["AH", "CH", "DH", "BH"]
regs16_lst = ["AX", "CX", "DX", "BX", "SI", "DI"]
regs32_lst = ["EAX", "ECX", "EDX", "EBX", "ESI", "EDI"]
regs64_lst = ["RAX", "RCX", "RDX", "RBX", "RSI", "RDI"]

# Stack-related GP registers
regs16_stack_lst = ["SP", "BP"]
regs32_stack_lst = ["ESP", "EBP"]
regs64_stack_lst = ["RSP", "RBP"]

# MMX registers
mmx_regs_lst = ['MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7']

# SSE registers
sse_regs_lst = ['XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7']

# word-sized arch mappings
acc_regs = {(8 | 0): 'AL', (8 | 1): 'AH', 16: 'AX', 32: 'EAX', 64: 'RAX'}
ctr_regs = {(8 | 0): 'CL', (8 | 1): 'CH', 16: 'CX',32: 'ECX', 64: 'RCX'}
data_regs = {(8 | 0): 'DL', (8 | 1): 'DH', 16: 'DX',32: 'EDX', 64: 'RDX'}
base_regs = {(8 | 0): 'BL', (8 | 1): 'BH', 16: 'BX',32: 'EBX', 64: 'RBX'}
dest_index_regs = {16: 'DI', 32: 'EDI', 64: 'RDI'}
src_index_regs = {16: 'SI', 32: 'ESI', 64: 'RSI'}

stackpointer_registers = {16: 'SP', 32: 'ESP', 64: 'RSP'}
stackframepointer_registers = {16: 'BP', 32: 'EBP', 64: 'RBP'}

word_keywords = {8: 'BYTE', 16: 'WORD', 32: 'DWORD', 64: 'QWORD'}
word_loads = {8: 'LODSB', 16: 'LODSW', 32: 'LODSD', 64: 'LODSQ'}

# Packing
byte_packs = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}
bit_packs = {8: '<B', 16: '<H', 32: '<I', 64: '<Q'}

# List of FPU instructions taken from MSF's shikata_ga_nai
"""
fpu_instructions = []
fpu_instructions += ["\t.byte 0xD9\n\t.byte 0x{:02x}\n".format(x) for x in xrange(0xE8, 0xEF)]
fpu_instructions += ["\t.byte 0xD9\n\t.byte 0x{:02x}\n".format(x) for x in xrange(0xC0, 0xD0)]
fpu_instructions += ["\t.byte 0xDA\n\t.byte 0x{:02x}\n".format(x) for x in xrange(0xC0, 0xE0)]
fpu_instructions += ["\t.byte 0xDB\n\t.byte 0x{:02x}\n".format(x) for x in xrange(0xC0, 0xE0)]
fpu_instructions += ["\t.byte 0xDD\n\t.byte 0x{:02x}\n".format(x) for x in xrange(0xC0, 0xC8)]
fpu_instructions += ["\t.byte 0xD9\n\t.byte 0xD0\n", "\t.byte 0xD9\n\t.byte 0xE1\n", "\t.byte 0xD9\n\t.byte 0xF6\n", "\t.byte 0xD9\n\t.byte 0xF7\n", "\t.byte 0xD9\n\t.byte 0xE5\n"]
"""
fpu_instructions = ['\t.byte 0xD9\n\t.byte 0xe8\n', '\t.byte 0xD9\n\t.byte 0xe9\n', '\t.byte 0xD9\n\t.byte 0xea\n', '\t.byte 0xD9\n\t.byte 0xeb\n', '\t.byte 0xD9\n\t.byte 0xec\n', '\t.byte 0xD9\n\t.byte 0xed\n', '\t.byte 0xD9\n\t.byte 0xee\n', '\t.byte 0xD9\n\t.byte 0xc0\n', '\t.byte 0xD9\n\t.byte 0xc1\n', '\t.byte 0xD9\n\t.byte 0xc2\n', '\t.byte 0xD9\n\t.byte 0xc3\n', '\t.byte 0xD9\n\t.byte 0xc4\n', '\t.byte 0xD9\n\t.byte 0xc5\n', '\t.byte 0xD9\n\t.byte 0xc6\n', '\t.byte 0xD9\n\t.byte 0xc7\n', '\t.byte 0xD9\n\t.byte 0xc8\n', '\t.byte 0xD9\n\t.byte 0xc9\n', '\t.byte 0xD9\n\t.byte 0xca\n', '\t.byte 0xD9\n\t.byte 0xcb\n', '\t.byte 0xD9\n\t.byte 0xcc\n', '\t.byte 0xD9\n\t.byte 0xcd\n', '\t.byte 0xD9\n\t.byte 0xce\n', '\t.byte 0xD9\n\t.byte 0xcf\n', '\t.byte 0xDA\n\t.byte 0xc0\n', '\t.byte 0xDA\n\t.byte 0xc1\n', '\t.byte 0xDA\n\t.byte 0xc2\n', '\t.byte 0xDA\n\t.byte 0xc3\n', '\t.byte 0xDA\n\t.byte 0xc4\n', '\t.byte 0xDA\n\t.byte 0xc5\n', '\t.byte 0xDA\n\t.byte 0xc6\n', '\t.byte 0xDA\n\t.byte 0xc7\n', '\t.byte 0xDA\n\t.byte 0xc8\n', '\t.byte 0xDA\n\t.byte 0xc9\n', '\t.byte 0xDA\n\t.byte 0xca\n', '\t.byte 0xDA\n\t.byte 0xcb\n', '\t.byte 0xDA\n\t.byte 0xcc\n', '\t.byte 0xDA\n\t.byte 0xcd\n', '\t.byte 0xDA\n\t.byte 0xce\n', '\t.byte 0xDA\n\t.byte 0xcf\n', '\t.byte 0xDA\n\t.byte 0xd0\n', '\t.byte 0xDA\n\t.byte 0xd1\n', '\t.byte 0xDA\n\t.byte 0xd2\n', '\t.byte 0xDA\n\t.byte 0xd3\n', '\t.byte 0xDA\n\t.byte 0xd4\n', '\t.byte 0xDA\n\t.byte 0xd5\n', '\t.byte 0xDA\n\t.byte 0xd6\n', '\t.byte 0xDA\n\t.byte 0xd7\n', '\t.byte 0xDA\n\t.byte 0xd8\n', '\t.byte 0xDA\n\t.byte 0xd9\n', '\t.byte 0xDA\n\t.byte 0xda\n', '\t.byte 0xDA\n\t.byte 0xdb\n', '\t.byte 0xDA\n\t.byte 0xdc\n', '\t.byte 0xDA\n\t.byte 0xdd\n', '\t.byte 0xDA\n\t.byte 0xde\n', '\t.byte 0xDA\n\t.byte 0xdf\n', '\t.byte 0xDB\n\t.byte 0xc0\n', '\t.byte 0xDB\n\t.byte 0xc1\n', '\t.byte 0xDB\n\t.byte 0xc2\n', '\t.byte 0xDB\n\t.byte 0xc3\n', '\t.byte 0xDB\n\t.byte 0xc4\n', '\t.byte 0xDB\n\t.byte 0xc5\n', '\t.byte 0xDB\n\t.byte 0xc6\n', '\t.byte 0xDB\n\t.byte 0xc7\n', '\t.byte 0xDB\n\t.byte 0xc8\n', '\t.byte 0xDB\n\t.byte 0xc9\n', '\t.byte 0xDB\n\t.byte 0xca\n', '\t.byte 0xDB\n\t.byte 0xcb\n', '\t.byte 0xDB\n\t.byte 0xcc\n', '\t.byte 0xDB\n\t.byte 0xcd\n', '\t.byte 0xDB\n\t.byte 0xce\n', '\t.byte 0xDB\n\t.byte 0xcf\n', '\t.byte 0xDB\n\t.byte 0xd0\n', '\t.byte 0xDB\n\t.byte 0xd1\n', '\t.byte 0xDB\n\t.byte 0xd2\n', '\t.byte 0xDB\n\t.byte 0xd3\n', '\t.byte 0xDB\n\t.byte 0xd4\n', '\t.byte 0xDB\n\t.byte 0xd5\n', '\t.byte 0xDB\n\t.byte 0xd6\n', '\t.byte 0xDB\n\t.byte 0xd7\n', '\t.byte 0xDB\n\t.byte 0xd8\n', '\t.byte 0xDB\n\t.byte 0xd9\n', '\t.byte 0xDB\n\t.byte 0xda\n', '\t.byte 0xDB\n\t.byte 0xdb\n', '\t.byte 0xDB\n\t.byte 0xdc\n', '\t.byte 0xDB\n\t.byte 0xdd\n', '\t.byte 0xDB\n\t.byte 0xde\n', '\t.byte 0xDB\n\t.byte 0xdf\n', '\t.byte 0xDD\n\t.byte 0xc0\n', '\t.byte 0xDD\n\t.byte 0xc1\n', '\t.byte 0xDD\n\t.byte 0xc2\n', '\t.byte 0xDD\n\t.byte 0xc3\n', '\t.byte 0xDD\n\t.byte 0xc4\n', '\t.byte 0xDD\n\t.byte 0xc5\n', '\t.byte 0xDD\n\t.byte 0xc6\n', '\t.byte 0xDD\n\t.byte 0xc7\n', '\t.byte 0xD9\n\t.byte 0xD0\n', '\t.byte 0xD9\n\t.byte 0xE1\n', '\t.byte 0xD9\n\t.byte 0xF6\n', '\t.byte 0xD9\n\t.byte 0xF7\n', '\t.byte 0xD9\n\t.byte 0xE5\n']

class arch_registers:
	def __init__(self, arch, bits):
		self.arch = arch
		self.bits = bits
		return

	def get_gp_regs(self, stack = False):
		regs = {16: regs16_lst+regs16_stack_lst if stack else regs16_lst,
				32: regs32_lst+regs32_stack_lst if stack else regs32_lst,
				64: regs64_lst+regs64_stack_lst if stack else regs64_lst}

		return regs[self.bits]

	# Return random non-blacklisted GP register (including stack-related registers or not)
	def random_gp_reg(self, stack = False, blacklist = []):
		regs = {32: regs32_lst+regs32_stack_lst if stack else regs32_lst,
				64: regs64_lst+regs64_stack_lst if stack else regs64_lst}

		return choice(list(set(regs[self.bits])-set(blacklist)))

	def random_mmx_reg(self, blacklist = []):
		return choice(list(set(mmx_regs_lst)-set(blacklist)))

	def random_sse_reg(self, blacklist = []):
		return choice(list(set(sse_regs_lst)-set(blacklist)))

	def gp_reg_to_size(self, reg, insize, outsize):
		regs = {16: regs16_lst+regs16_stack_lst,
				32: regs32_lst+regs32_stack_lst,
				64: regs64_lst+regs64_stack_lst}

		index = regs[insize].index(reg)

		# Low	
		if(outsize == (8 | 0)):
			ret = regs08_low_lst[index]
		# High
		elif(outsize == (8 | 1)):
			ret = regs08_high_lst[index]
		else:
			ret = regs[outsize][index]

		return ret

	# Register index in our list
	def gp_reg_to_index(self, reg):
		regs = {32: regs32_lst+regs32_stack_lst,
				64: regs64_lst+regs64_stack_lst}

		return regs[self.bits].index(reg)

	# Opcode index for registers
	def gp_reg_to_opcode_index(self, reg):
		regs = {32: regs32_lst+regs32_stack_lst,
				64: regs64_lst+regs64_stack_lst}

		index = regs[self.bits].index(reg)
		if((reg == src_index_regs[self.bits]) or (reg == dest_index_regs[self.bits])):
			index += 2
		return index

	def mmx_reg_to_index(self, reg):
		return mmx_regs_lst.index(reg)

	def sse_reg_to_index(self, reg):
		return sse_regs_lst.index(reg)