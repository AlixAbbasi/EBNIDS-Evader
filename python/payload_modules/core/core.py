#!/usr/bin/python

"""
payload core template, methods can be overridden to implement specific functionality
"""

class payload_module:
	def __init__(self, arch, bits, badchars = ""):
		self.arch = arch
		self.bits = bits
		self.badchars = badchars
		return