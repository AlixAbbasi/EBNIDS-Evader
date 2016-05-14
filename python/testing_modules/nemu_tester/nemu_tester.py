#!/usr/bin/python

"""
Nemu evasion testing module
"""

import nemu
import string

class nemu_evasion_test:
	def __init__(self, arch, bits):
		self.arch = arch
		self.bits = bits
		return

	def test(self, payload):
		starting_pos = -1
		shellcode_type = ""
		decrypted_shellcode = ""

		res = nemu.emulate(payload)
		if res == -1:
			status = False
		else:
			status = True
			starting_pos = res
			res = nemu.emulate_trace(payload) #buffer = payload, check_all_pos = 1, exec_threshold = 1024
			shellcode_type = nemu.print_match_type(res[8])
			decrypted_len = res[15]
			
			if decrypted_len > 0:
				BINFILTER = ''.join([chr(x) in string.printable and chr(x) or '.' for x in range(256)])
				decrypted_shellcode = res[16].translate(BINFILTER)

		return status, starting_pos, shellcode_type, decrypted_shellcode
