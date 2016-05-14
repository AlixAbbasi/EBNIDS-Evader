#!/usr/bin/python

"""
Core component tying encoder/evader chain together
"""

from miasm2.arch.x86.arch import mn_x86

from arch.core import arch_registers, ctr_regs, architectures
from assembler.assembler import assembler
from assembler.disassembler import disassembler

# Config
from utils.config import select_evader, select_encoder
from utils.conflict_resolver import conflict_resolver
from utils.dependency_settings import dependency_settings

class ebnids_evasion_encoder:
	def __init__(self):
		return

	def encode(self, payload, evasion_chain, arch = mn_x86, bits = 32, badchars = ""):
		encoded_payload = payload

		for e_option in evasion_chain:
			regs = arch_registers(arch, bits)

			# Counter register is blacklisted due to usage in subsequent decoding loops
			blacklist = [ctr_regs[bits]]

			# GetPC dest reg
			getpc_reg = regs.random_gp_reg(False, blacklist)

			# no reuse of getpc reg
			blacklist += [getpc_reg]

			# Key registry
			key_reg = regs.random_gp_reg(False, blacklist)

			# no reuse of key reg
			blacklist += [key_reg]

			# Encoder
			encoder = e_option['encoder'](encoded_payload)

			key_size = encoder.get_key_size()

			if 'key' in e_option['additional_params']:
				key = e_option['additional_params']['key']
			else:
				key = encoder.find_key(badchars)

			# Encoded payload
			enc = encoder.encode(key, badchars)

			# Evader
			evader = e_option['evader'](arch, bits, badchars)

			evader.set_encoded_payload(enc)
			evader.set_additional_params(e_option['additional_params'])

			# Key filler
			keyfiller_stub = evader.keyfiller_stub(key_reg, key)
			evader.set_keyfiller_stub(keyfiller_stub)

			# Decoder stub
			decoder_stub = encoder.decoder_stub(getpc_reg, key_reg, len(keyfiller_stub), arch, bits)
			evader.set_decoder_stub(decoder_stub)

			# GetPC stub
			getpc_stub = evader.getpc_stub(getpc_reg)
			stubs = getpc_stub + keyfiller_stub + decoder_stub

			# Prepend stubs to encoded payload
			encoded_payload = stubs + enc

			# Use evader's custom layer encoder when necessary (eg. for hash armoring, stack constructor, etc.)
			if(evader.has_layer_encoder()):
				encoded_payload = evader.encode(encoded_payload, badchars)

		return encoded_payload

	def armor(self, payload, evasion_chain, arch = mn_x86, bits = 32, badchars = "", auto_resolve = False):

		if(auto_resolve):
			dep_set = dependency_settings()
			dep_specs = dep_set.get_dependencies()

			resolver = conflict_resolver(dep_specs)
			ordered_chain = resolver.resolve(evasion_chain)
		else:
			ordered_chain = evasion_chain

		final_chain = []
		name_chain = []

		for element in ordered_chain:
			name, evader = element
			name_chain.append(name)
			final_chain.append(evader)

		print "[+]Selected Evader chain order: [%s]" % ",".join(name_chain)

		return name_chain, self.encode(payload, final_chain, arch, bits, badchars)

def construct_chain(evade, depth, encoders):
	evasion_chain = []
	for ebnids in evade:
		appendage = []
		item = select_evader(ebnids, depth)

		for element in item:
			name, evader = element
			# Select random encoder from whitelist
			encoder = select_encoder(encoders)
			appendage.append((name, {'evader': evader, 'encoder': encoder, 'additional_params': {}}))

		evasion_chain += appendage
	return evasion_chain

def armor_shellcode(shellcode, architecture, bits, badchars, evade, depth, encoders, auto_resolve):
	arch = architectures[architecture]

	evasion_chain = construct_chain(evade, depth, encoders)

	ebnids_evade = ebnids_evasion_encoder()
	name_chain, encoded_shellcode = ebnids_evade.armor(shellcode, evasion_chain, arch, bits, badchars, auto_resolve)
	return name_chain, encoded_shellcode