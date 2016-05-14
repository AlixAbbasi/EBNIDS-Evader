# -*- coding: binary -*-

# =============================================================
# KeyGen stub generation
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids

  # CKPE keygen type constants
  MEM_ADDRESS = 0

  # KeyGen stub generator
  class KeyGen

    #
    # Generate minimally polymorphic CKPE keygen stub
    #
    # Pre:
    #       - storeReg specifies register in which to store key
    #       - data is the datastore variable
    #
    # Post:
    #       - storeReg holds key
    #
    # Improvements:
    #       - more keyGen types
    #       - Stronger polymorphism
    #
    def self.keyGen(storeReg, data, badchars)

    	if(not data.has_key?("CKPE_TYPE"))
    		raise "[-]No CKPE_TYPE specified."
    	end

		case data['CKPE_TYPE'].to_i
			when MEM_ADDRESS
		    	if(not data.has_key?("CKPE_MEMORY_ADDRESS"))
		    		raise "[-]No CKPE_MEMORY_ADDRESS specified."
		    	end

				address = data['CKPE_MEMORY_ADDRESS'].hex
				key_Gen = Rex::Poly::LogicalBlock.new('key_Gen',*memAddressKeyGen_instructions(storeReg, address, badchars))
			else
				raise "[-]Invalid CKPE_TYPE specified."
		end

		return key_Gen.generate()
    end

    #
    # Returns the light-polymorphic set of memory-address based CKPE keygen stubs
    #
    # TODO: support MSF's EnableContextEncoding model (use XORK instead of address and let MSF handle the rest)
    #       if CKPE_MEMORY_ADDRESS is set we use our method, otherwise MSF's EnableContextEncoding method
    #
    #       Obviously this doesn't go for other keygen methods as they don't rely on a memory address etc.
    #
    #                  real_key = state.context_address if (state.context_encoding)
    # 
    # Improvements:
    #        - More variations
    #        - Stronger polymorphism
    #
	def self.memAddressKeyGen_instructions(storeReg, address, badchars)

		gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

		# Random register
		reg1 = gp_regs[Random.rand(6)]

		keyGens = []

		keyGens << "\x8B" + (0x05 + (8 * storeReg)).chr + Rex::Arch::X86.pack_dword(address) # mov storeReg, [address]

		keyGens << Rex::Arch::X86.mov_dword(reg1, address) + # mov reg1, address
				   "\x8B" + (0x00 + reg1 + (8 * storeReg)).chr # mov storeReg, [reg1]

		keyGens << "\xFF\x35" + Rex::Arch::X86.pack_dword(address) + # push [address]
				   Rex::Arch::X86.pop_dword(storeReg) # pop storeReg

		keyGens << Rex::Arch::X86.mov_dword(reg1, address) + # mov reg1, address
				   "\xFF" + (0x30 + reg1).chr + # push [reg1]
				   Rex::Arch::X86.pop_dword(storeReg) # pop storeReg

		keyGens
	end


  end


end