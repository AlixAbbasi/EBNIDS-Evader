#!/usr/bin/python

"""
For generating some testing payloads and payload-embedded evasion techniques
"""

from miasm2.arch.x86.arch import mn_x86

from arch.core import arch_registers
from assembler.assembler import assembler
from assembler.disassembler import disassembler

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


arch = mn_x86
bits = 32
badchars = ""

regs = arch_registers(arch, bits)
base_reg = regs.random_gp_reg(False, [])

base_getter = payload_kernel32_stackframe_walker(arch, bits, badchars)
kernel32_base_resolution_stub = base_getter.get_stub(base_reg)

k = "db "
for b in kernel32_base_resolution_stub:
	k += "0x{:02x}, ".format(ord(b))

k += "0x90"

print k