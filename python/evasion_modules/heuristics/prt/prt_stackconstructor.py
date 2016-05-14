#!/usr/bin/python

"""
Direct clone of getpc stack constructor which also evades PRT heuristc
"""

from evasion_modules.heuristics.getpc.getpc_stackconstruct import evasion_getpc_stackconstruct

class evasion_ptr_stackconstruct(evasion_getpc_stackconstruct):
	pass