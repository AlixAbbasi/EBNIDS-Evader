#!/usr/bin/python

"""
IKTOMI - EBNIDS Evasion Encoder
Copyright (C) 2015 - Ali Abbasi and Jos Wetzels.

IKTOMI is a proof-of-concept implementation of the EBNIDS evasion modules as a shellcode encoding framework accompanying the papers 'On Emulation-Based Network Intrusion Detection Systems' and APTs way: Evading Your EBNIDS. 
"""

import argparse

# Core
from evader_core.ebnids_evasion import armor_shellcode

# Config
from utils.config import encoder_options

# Bytework
from utils.bytework import translate_bytes

# Sanity check
from sanity import sanity_test

# Command-line argument parsing functionality
class arg_parser(argparse.ArgumentParser):
    def error(self, message):
        print "[-]Error: %s\n" % message
        self.print_help()
        exit()

# Command-line argument parser
def get_arg_parser():
	header = ""

	parser = arg_parser(description=header)	
	parser.add_argument('--shellcode', dest='shellcode', help='shellcode (in hex format)', required=True)

	parser.add_argument('--evade', dest='evade', help='list of target EBNIDSes to evade', nargs='+', choices=['libemu', 'nemu'])
	parser.add_argument('--depth', dest='depth', help='number of evaders to chain per target EBNIDS (default: 1)', default=1, type=int)

	parser.add_argument('--encoders', dest='encoders', help='list of encoders to be (randomly) chosen from', nargs='+', choices=[x for x in encoder_options()])

	parser.add_argument('--no-auto_resolve', dest='auto_resolve', help='keep user specified evasion chain order (default: auto-resolve)', action='store_false')
	parser.set_defaults(auto_resolve=True)

	parser.add_argument('--sanity', dest='sanity', help='sanity test', choices=['full', 'kernel32'])
	
	parser.add_argument('--arch', dest='architecture', help='architecture (default: x86)', default='x86', choices=['x86'])
	parser.add_argument('--bits', dest='bits', type=int, help='bits (default: 32)', default=32, choices=[32])
	parser.add_argument('--badchars', dest='badchars', help='badchars (in hex format eg. 000a)', default="")

	parser.add_argument('--format', dest='outformat', help='output format', choices=['hex','c','asm','python'], default="hex")

	return parser

def show_banner():
	banner = """
:IKTOMI.IKTOMI.IKTOMI.IKTOMI.IKTOMI.IKTOMI:
 ___________$___________$
_____$____$$___________$$____$
____$$____$$____________$$___$$
____$$___$$_____________$$____$
___$$____$$____$___$____$$____$$
___$$____$$____$$$$$____$$____$$
___$$___$$$___$$$$$$$___$$$___$$
__$$$___$$$___$$$$$$$___$$$___$$$
__$$$___$$$___$$$$$$$___$$$___$$$
__$$$___$$$____$$$$$____$$$___$$$
__$$$____$$$___$$$$$___$$$___$$$$
___$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
__________$$$$$$$$$$$$$$
___________$$$$$$$$$$$$
_____$$$$$$$$$$$$$$$$$$$$$$$$$
_$$$$$$$$$$_$$$$$$$$$$$_$$$$$$$$$$
$$$$___$$$__$$$$$$$$$$$__$$$___$$$$
$$$____$$$__$$$$$$$$$$$__$$$____$$$
_$$$___$$$__$$$$$$$$$$$__$$$___$$$
_$$$___$$$__$$$$$$$$$$$__$$$___$$$
__$$____$$___$$$$$$$$$___$$____$$
__$$$___$$___$$$$$$$$$___$$___$$$
___$$____$$___$$$$$$$___$$____$$
____$$____$____$$$$$____$____$$
_____$_____$___________$_____$
______$____$___________$____$

EBNIDS Evasion Encoder
Copyright (C) 2015 - Jos Wetzels.
"""
	print banner
	return

def main():
	show_banner()
	parser = get_arg_parser()
	args = parser.parse_args()

	if(args.sanity):
		sanity_t = sanity_test()
		if(args.sanity == 'full'):
			sanity_t.full_sanity_test(args.architecture, args.bits, args.badchars.decode('hex'))
		elif(args.sanity == 'kernel32'):
			sanity_t.calc_shellcode_sanity_test(args.architecture, args.bits, args.badchars.decode('hex'))
	else:
		name_chain, encoded_shellcode = armor_shellcode(args.shellcode.decode('hex'), args.architecture, args.bits, args.badchars.decode('hex'), args.evade, args.depth, args.encoders, args.auto_resolve)

		print "[+]Armored shellcode: "
		print translate_bytes(encoded_shellcode, args.outformat)

	return

if __name__ == "__main__":
	main()