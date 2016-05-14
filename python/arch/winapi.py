#!/usr/bin/python

"""
Some basic windows constants and address lookup functionality
Database has very limited support for now
"""

import sqlite3

page_read_write_execute = 0x40
page_exec_read_write_commit = 0x08000040

filemap_read_write = 0x6
filemap_read_write_execute = 0x26

mem_commit = 0x1000

class syscall_db:
	def __init__(self, os_version, service_pack):
		self.os_version = os_version
		self.service_pack = service_pack
		return

	def connect(self, db_filename):
		try:
			self.conn = sqlite3.connect(db_filename)
			self.c = self.conn.cursor()
			return
		except:
			raise Exception("[-]connect: could not connect to database [%s]" % db_filename)

	"""
	Function to lookup SYSCALL numbers corresponding to given OS version/Service Pack
	This could be supplemented by a function generating a stub determining the information dynamically and selecting the syscall number on that basis
	"""

	def get_syscall_number(self, syscall_name):
		t = (syscall_name, self.os_version, self.service_pack, )
		results = []

		for row in self.c.execute('SELECT * FROM syscalls WHERE syscall_name=? AND os_version=? AND service_pack=?', t):
			results.append(row)

		if(len(results) == 1):
			return results[0][2]
		else:
			raise Exception("[-]get_function_address: either no or multiple functions match selection criteria")

class winapi_db:
	def __init__(self, os_version, service_pack, language_pack):
		self.os_version = os_version
		self.service_pack = service_pack
		self.language_pack = language_pack
		return

	def connect(self, db_filename):
		try:
			self.conn = sqlite3.connect(db_filename)
			self.c = self.conn.cursor()
			return
		except:
			raise Exception("[-]connect: could not connect to database [%s]" % db_filename)

	"""
	Function to lookup API address in DLL corresponding to given OS version/Service Pack/Language Pack
	Using direct addressing makes shellcode less reliable (or rather, more targeted) but means we won't have to include function resolution code

	Note that this will obviously not work on systems with ASLR enabled
	"""

	def get_function_address(self, function_name, library_name):
		t = (function_name, library_name, self.os_version, self.service_pack, self.language_pack, )
		results = []

		for row in self.c.execute('SELECT * FROM function_addresses WHERE function_name=? AND library_name=? AND os_version=? AND service_pack=? AND language_pack=?', t):
			results.append(row)

		if(len(results) == 1):
			return results[0][3]
		else:
			raise Exception("[-]get_function_address: either no or multiple functions match selection criteria")