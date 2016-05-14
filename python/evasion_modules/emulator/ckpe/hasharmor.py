#!/usr/bin/python

"""
Hash armoring
Hash-based shellcode encoding armor

Currently only supports windows platform
"""

from random import choice
from struct import pack, unpack
from hashlib import sha1
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.keygen import keygen_stub_builder
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, word_keywords, arch_registers, bit_packs, acc_regs
from utils.bytework import bytes_to_asm, contains_badchars

class evasion_ckpe_hasharmor(evasion_module):

	def has_layer_encoder(self):
		return True

    #
    # Overriden method to fill key registery
    # No returned code here because this is handled by getPCStub as key generation for hashamroring is CKPE style
    #
	def keyfiller_stub(self, key_reg, key):
		self.key_reg = key_reg
		self.key_val = key
		return ""

	# simple getpc stub to be prepended to to-be-encoded payload
	def getpc_stub(self, getpc_reg):

		stackpointer_reg = stackpointer_registers[self.bits]

		# Build stack-based getPC code, store PC in getPCDestReg
		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		stack_getpc_stub = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		variables = {'stack_getpc_stub': stack_getpc_stub, 'stackpointer_reg': stackpointer_reg}

		listing = '''
main:
	PUSH {stack_getpc_stub}
	CALL {stackpointer_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

    # 
    # Hasharmor encoding routine
    #
    # [*] Note:
    #     - Can be improved by supporting multiple platforms
    #     - Can be improved by using full key in encoded GetPC stub as well
    #
	def encode(self, buf, badchars):

		acc_reg = acc_regs[self.bits]

		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		encoded_getpc_stub = (unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(acc_reg))[0] ^ unpack(bit_packs[self.bits], self.key_val)[0])

		#kernel32.dll base address resolution
		#TODO: kernel32_base_resolution = baseResolution.resolveKernel32(data['KERNEL32_METHOD'].to_i)

		# TODO: we need 128-bit key covering 4 registers here
		keygen_builder = keygen_stub_builder(self.arch, self.bits, self.badchars)
		keygen_stub = bytes_to_asm(keygen_builder.ckpe_keygen_stub(self.key_reg, self.additional_params['ckpe_method'], self.additional_params['ckpe_params']))

		# Salt is 16-bit sized word (lower bound 1, upper bound max_short - 1)
		armored_data = self.armor_sequence(buf, 16)

		variables = {}

		# TODO:
		listing = '''
main:

'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

	# Hash-armor sequence of bytes
	def armor_sequence(self, b_sequence, salt_bitsize):
		offset = 0
		a_sequence = ""

		while(offset < len(b_sequence)):
			b_run = b_sequence[offset: offset+2]

			a_run = self.armor_run(b_run, salt_bitsize)
			
			if(a_run == False):
				raise Exception("[-]armor_sequence: could not armor run [%s]" % a_run.encode('hex'))

			packed_salt, packed_lb, packed_ub = a_run

			for b in packed_salt:
				a_sequence += "\t.byte 0x{:02x}\n".format(ord(b))

			for b in packed_lb:
				a_sequence += "\t.byte 0x{:02x}\n".format(ord(b))

			for b in packed_ub:
				a_sequence += "\t.byte 0x{:02x}\n".format(ord(b))

			offset += 2

		return a_sequence

	# Hash-armor single run
	def armor_run(self, b_run, salt_bitsize):
		lower_bound = (0 + 1)
		upper_bound = (2**salt_bitsize)

		for salt in xrange(lower_bound, upper_bound):
			packed_salt = pack(bit_packs[salt_bitsize], salt)

			# Salt cannot contain badchars
			if not(contains_badchars(packed_salt, self.badchars)):
				h = sha1(self.key_val + packed_salt).digest()
				# Does this salt produce hash containing our run?
				if (b_run in h):
					lb = h.index(b_run)
					ub = lb + len(b_run)
					packed_lb = pack(bit_packs[salt_bitsize], lb)
					packed_ub = pack(bit_packs[salt_bitsize], ub)

					# neither lb nor ub may contain null-bytes or badchars
					if(not(contains_badchars(packed_lb, self.badchars+"\x00") or contains_badchars(packed_ub, self.badchars+"\x00"))):
						return packed_salt, packed_lb, packed_ub

		return False