#!/usr/bin/python

"""
Timing-based emulator detection
Anti-emulation armor integrating timing-based detection
"""

from struct import unpack
from random import choice, shuffle
from assembler.assembler import assembler
from evasion_modules.core.core import evasion_module
from evasion_modules.core.getpc import getpc_stub_builder
from arch.core import stackpointer_registers, stackframepointer_registers, acc_regs, ctr_regs, data_regs, dest_index_regs, src_index_regs, arch_registers, bit_packs, word_keywords

class evasion_detect_timing(evasion_module):

    #
    # getPC stub incorporating timing-based emulator detection
    #
    #
    # [*] Note:
    #       - This can be futher improved by making it polymorphic
    #
	def getpc_stub(self, getpc_reg):
		reg_size = 2**self.bits

		stackpointer_reg = stackpointer_registers[self.bits]
		word_keyword = word_keywords[self.bits]

		regs = arch_registers(self.arch, self.bits)
		call_reg = regs.random_gp_reg(False, [])

		acc_reg = acc_regs[self.bits]
		ctr_reg = ctr_regs[self.bits]
		data_reg = data_regs[self.bits]
		src_index_reg = src_index_regs[self.bits]
		dest_index_reg = dest_index_regs[self.bits]

		# null instruction
		null_instructions = ['XOR', 'SUB']
		null_instr = choice(null_instructions)

		rdtscp_instruction = "\t.byte 0x0F\n\t.byte 0x01\n\t.byte 0xF9\n"

		# Build stack-based getPC code, store PC in getPCDestReg
		stub_builder = getpc_stub_builder(self.arch, self.bits, self.badchars)
		getpc_instruction = unpack(bit_packs[self.bits], stub_builder.stack_getpc_stub(getpc_reg))[0]

		variables = {'rdtscp_instruction': rdtscp_instruction, 'word_keyword': word_keyword, 'reg_size': reg_size, 'acc_reg': acc_reg, 'ctr_reg': ctr_reg, 'data_reg': data_reg, 'src_index_reg': src_index_reg, 'dest_index_reg': dest_index_reg, 'null_instr': null_instr, 'stackpointer_reg': stackpointer_reg, 'call_reg': call_reg, 'getpc_instruction': getpc_instruction}

		listing = '''
main:
	XOR {ctr_reg}, {ctr_reg}
	SUB {ctr_reg}, (-2 % {reg_size})

timing_loop:
	PUSH {ctr_reg}

	; serialize to prevent out-of-order execution
	CPUID
	; read clock
	RDTSC
	; restore counter garbled by CPUID
	MOV {ctr_reg}, {word_keyword} PTR [{stackpointer_reg}]

	; TSC in EDX:EAX (higher order 32bits into edx, lower order 32 bits into eax)
 	; consider only (1st 3 bytes of) lower order bits because loop won't run long enough to affect edx

 	PUSH {acc_reg}

start_check: 	
	CMP {ctr_reg}, 2
	JB second_pass

	first_pass:
		XOR {ctr_reg}, {ctr_reg}
		SUB {ctr_reg}, (-0xFF % {reg_size})

		first_loop:
			NOP
		LOOP first_loop

		JMP end_check

	second_pass:
		XOR {ctr_reg}, {ctr_reg}
		SUB {ctr_reg}, (-0xFF % {reg_size})

		second_loop:
			LEA {acc_reg}, {word_keyword} PTR [{acc_reg} + {ctr_reg}]
			IMUL {ctr_reg}
		LOOP second_loop
end_check:
	
	; read clock second time (guarantee all code in between has been executed)
	{rdtscp_instruction}

	PUSH {acc_reg}
	CPUID
	POP {acc_reg}
	POP {data_reg}
	SUB {acc_reg}, {data_reg}
	; only interested in first 3 bytes of dword (more accurate measurements would yield false positives on non-emulators,etc.)
	SHR {acc_reg}, 8

	POP {ctr_reg}
	CMP {ctr_reg}, 2

	; first pass result
	CMOVZ {src_index_reg}, {acc_reg}
	; second pass result
	CMOVNZ {dest_index_reg}, {acc_reg}

	; MIASM assembler gave trouble trying to assemble loop so we solve it like this
	DEC {ctr_reg}
	TEST {ctr_reg}, {ctr_reg}
	JNZ timing_loop

	{null_instr} {data_reg}, {data_reg}
	MOV {acc_reg}, {dest_index_reg}
	IDIV {src_index_reg}

	PUSH {getpc_instruction}

	CMP {acc_reg}, (1+5)	
	CMOVLE {call_reg}, {stackpointer_reg}
	CALL {call_reg}
'''

		asm = assembler(self.arch, self.bits)
		stub = asm.assemble(listing.format(**variables))
		return stub