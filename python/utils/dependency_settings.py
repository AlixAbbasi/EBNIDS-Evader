#!/usr/bin/python

"""
Contains all inter-encoder dependency settings
"""

# Evaders

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

class dependency_settings:
	def __init__(self):
		self.dependencies = {}

		# TODO: write out all dependencies here

		self.dependencies[evasion_antidisassembly] = []

		self.dependencies[evasion_getpc_stackscan] = [evasion_antidisassembly, evasion_getpc_stackconstruct, evasion_prt_relocator, evasion_ptr_stackconstruct, evasion_wx_dualmap, evasion_egghunt_api, evasion_faith_fpu, evasion_faith_mmx, evasion_faith_sse, evasion_faith_obsol, evasion_detect_libemu, evasion_detect_nemu_gp, evasion_detect_nemu_cpuid, evasion_detect_timing, evasion_timeout_opaque_loop, evasion_timeout_intensive_loop, evasion_timeout_integrated_loop, evasion_timeout_integrated_loop]
		self.dependencies[evasion_getpc_stackconstruct] = []

		self.dependencies[evasion_prt_relocator] = [evasion_ckpe_ckpe]
		self.dependencies[evasion_ptr_stackconstruct] = []

		self.dependencies[evasion_wx_dualmap] = []
		self.dependencies[evasion_egghunt_api] = []

		# TODO: kernel32 heuristic

		self.dependencies[evasion_faith_fpu] = []
		self.dependencies[evasion_faith_mmx] = []
		self.dependencies[evasion_faith_sse] = []
		self.dependencies[evasion_faith_obsol] = []

		self.dependencies[evasion_detect_libemu] = []
		self.dependencies[evasion_detect_nemu_gp] = []
		self.dependencies[evasion_detect_nemu_cpuid] = []
		self.dependencies[evasion_detect_timing] = []

		self.dependencies[evasion_timeout_opaque_loop] = []
		self.dependencies[evasion_timeout_intensive_loop] = []
		self.dependencies[evasion_timeout_integrated_loop] = []

		self.dependencies[evasion_timeout_rda] = []

		self.dependencies[evasion_ckpe_ckpe] = []
		return

	def get_dependencies(self):
		return self.dependencies