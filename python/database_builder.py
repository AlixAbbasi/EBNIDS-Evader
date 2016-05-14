
#TODO: this is dummy code, not yet ready
from ctypes import *	

class db_builder:
	def __init__(self, db, os_version, service_pack, language_pack):
		self.db = db
		return

	def get_address(self, library_name, function_name):
		handle = windll.kernel32.LoadLibraryA(library_name.encode(encoding='ascii'))
		if(handle != 0):
			return windll.kernel32.GetProcAddress(handle, function_name.encode(encoding='ascii'))
		else:
			return 0

	def import_library(self, library_name):
		addr = self.get_address(library_name, "ExitProcess")
		print hex(addr)
		return

builder = db_builder("./arch/dll_db.sqlite", "WIN_7_ULTIMATE", "SP1", "EN")

builder.import_library("kernel32.dll")

#0x771679c8