#!/usr/bin/python

"""
Class contains config element coupling evaders to specific systems (eg. libemu, nemu)
for general purpose encoder auto-selection functionality.

Note: only those evaders which do not require additional parameters are considered
"""

from random import choice

# Encoders
from encoder_modules.poly_dword_xor import poly_dword_xor
from encoder_modules.poly_dword_speck import poly_dword_speck

# ===================
# Preprocessor
# ===================
# Anti-disassembly
from evasion_modules.preprocessor.antidisasm import evasion_antidisassembly

# ===================
# Heuristic
# ===================
# GetPC
# -------------------
from evasion_modules.heuristics.getpc.getpc_stackscan import evasion_getpc_stackscan
from evasion_modules.heuristics.getpc.getpc_stackconstruct import evasion_getpc_stackconstruct
# -------------------
# PRT
# -------------------
from evasion_modules.heuristics.prt.prt_relocator import evasion_prt_relocator
from evasion_modules.heuristics.prt.prt_stackconstructor import evasion_ptr_stackconstruct
# -------------------
# WX
# -------------------
from evasion_modules.heuristics.wx.wx_dualmap import evasion_wx_dualmap
# -------------------
# Egghunting
# -------------------
from evasion_modules.heuristics.egghunt.egghunt_api import evasion_egghunt_api

# ===================
# Emulator
# ===================
# Faithful emulation
from evasion_modules.emulator.faith.faith_fpu import evasion_faith_fpu
from evasion_modules.emulator.faith.faith_mmx import evasion_faith_mmx
from evasion_modules.emulator.faith.faith_sse import evasion_faith_sse
from evasion_modules.emulator.faith.faith_obsol import evasion_faith_obsol
# -------------------
# Emulator detection
# -------------------
from evasion_modules.emulator.detect.detect_libemu import evasion_detect_libemu
from evasion_modules.emulator.detect.detect_nemu_gp import evasion_detect_nemu_gp
from evasion_modules.emulator.detect.detect_nemu_cpuid import evasion_detect_nemu_cpuid
from evasion_modules.emulator.detect.detect_timing import evasion_detect_timing
# -------------------
# Timeout
# -------------------
from evasion_modules.emulator.timeout.timeout_loops import evasion_timeout_opaque_loop
from evasion_modules.emulator.timeout.timeout_loops import evasion_timeout_intensive_loop
from evasion_modules.emulator.timeout.timeout_loops import evasion_timeout_integrated_loop
from evasion_modules.emulator.timeout.timeout_rda import evasion_timeout_rda
# -------------------
# CKPE
# -------------------
from evasion_modules.emulator.ckpe.ckpe import evasion_ckpe_ckpe

encoders_config = {'x86.poly_dword_xor': poly_dword_xor}

evaders_config = {'libemu': [
							('heur.getpc.stack_scan', evasion_getpc_stackscan),
							('heur.getpc.stack_construct', evasion_getpc_stackconstruct),
							('heur.prt.stack_construct', evasion_ptr_stackconstruct),
							('emu.faith.fpu', evasion_faith_fpu),
							('emu.faith.mmx', evasion_faith_mmx),
							('emu.faith.sse', evasion_faith_sse),
							('emu.faith.obsol', evasion_faith_obsol),
							('emu.detect.libemu', evasion_detect_libemu),
							('emu.detect.timing', evasion_detect_timing),
							('emu.timeout.opaque_loop', evasion_timeout_opaque_loop),
							('emu.timeout.intensive_loop', evasion_timeout_intensive_loop),
							('emu.timeout.integrated_loop', evasion_timeout_integrated_loop),
							('emu.timeout.rda', evasion_timeout_rda)
						 	],
			   	    'nemu': [
							('heur.getpc.stack_scan', evasion_getpc_stackscan),
							# While the below two technically evade parts of nemu, they do not do fully so if the kernel32.dll heuristic is not evaded
							# ('heur.getpc.stack_construct', evasion_getpc_stackconstruct),
							# ('heur.prt.stack_construct', evasion_ptr_stackconstruct),
							('emu.faith.fpu', evasion_faith_fpu),
							('emu.faith.mmx', evasion_faith_mmx),
							('emu.faith.sse', evasion_faith_sse),
							('emu.detect.nemu_gp', evasion_detect_nemu_gp),
							('emu.detect.nemu_cpuid', evasion_detect_nemu_cpuid),
							('emu.detect.timing', evasion_detect_timing),
							('emu.timeout.integrated_loop', evasion_timeout_integrated_loop),
							('emu.timeout.rda', evasion_timeout_rda)
						 	]}

def select_evader(ebnids, depth):
	evasion_chain = []
	evaders = evaders_config[ebnids]

	if(depth > len(evaders)):
		raise Exception("[-]Depth %d too big for ebnids choice [%s]" % (depth, ebnids))

	for i in xrange(depth):
		pick = choice(evaders)
		evasion_chain.append(pick)
		evaders.remove(pick)

	return evasion_chain

def encoder_options():
	return encoders_config

def select_encoder(encoders):
	return encoders_config[choice(encoders)]