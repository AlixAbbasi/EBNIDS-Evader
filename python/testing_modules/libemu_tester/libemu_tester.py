#!/usr/bin/python

"""
Libemu evasion testing module
"""

from pylibemu import Emulator

class libemu_evasion_test:
	def __init__(self, arch, bits):
		self.arch = arch
		self.bits = bits
		self.emulator = Emulator()
		return

	def getPC_Test(self, shellcode):
		offset = -1
		profile = ""

		self.emulator.new()
		self.emulator.run(shellcode)

		if(self.emulator.offset >= 0):
			offset = self.emulator.offset
			profile = self.emulator.emu_profile_output.decode('utf-8')
			#if self.emulator.emu_profile_truncated:
			#	print "[WARNING] Emulation profile truncated"
			status = True
		else:
			status = False

		self.emulator.free()
		return status, offset, profile