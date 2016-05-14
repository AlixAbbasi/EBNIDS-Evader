# -*- coding: binary -*-

# =============================================================
# Armoring sub-module parent classes
#
# @Author: Jos Wetzels
# =============================================================

module Ebnids

  # Generic master parent class
  class Armor

    #
    # Creates an instance of an abstract Armor using the supplied information
    # hash.
    #
    def initialize(info = {})
      # set default info
      set_defaults

      # set supplied info
      info.each do |key, arg|
        @module_info[key] = arg
      end

      @module_metadata
    end

    #
    # Sets the modules unsupplied info fields to their default values.
    #
    def set_defaults
      @module_info = {
        'Name'         => 'No module name',           # Armor name
        'ID'           => 0,                          # Module ID
        'Description'  => 'No module description',    # Description
        'Author'       => 'No author',                # Author
        'License'      => MSF_LICENSE,                # License
        'Target'       => nil,                        # Target detection technique this armor protects against
        'SizeIncrease' => 0,                           # Size increase (in bytes) resulting from using this armor
        'isGetPC'      => 0,                          # Specifies whether armor serves as getPC stub
        'hasEncoder'   => 0,                          # Specifies whether armor has custom encoding functionality
        'Conflicts'    => [],                         # Array of incompatible amoring sub-module IDs
        'PreDeps'      => [],                         # Array of pre-dependent armoring sub-module IDs (ie. which should precede this one if combined)
        'PostDeps'     => []                          # Array of post-dependent armoring sub-module IDs (ie. which should succeed this one if combined)       
      }
    end

    #
    # Get property
    #
    def getProperty(name)
      return @module_info[name]
    end

    #
    # Virtual method for meta-data initialization
    # Has to be called before all other methods
    #
    def initMetaData(metadata = {})
      @module_metadata = metadata
    end

    #
    # Update/insert a metadata element
    #
    def updateMetadata(hashKey = nil, newValue = nil)
      if(@module_metadata != nil)
        @module_metadata[hashKey] = newValue
      end
    end

    #
    # Virtual method for filling the key register (used by the decoder stub) with a placeholder for the key (to be replaced by the calling encoder later), can be overriden by encoders using custom keygen methods
    #
    def fillKeyReg(keyReg, keyVal)
      fillKey = Rex::Poly::LogicalBlock.new('fillKeyReg',*fillKeyReg_instructions(keyReg, keyVal))
      return fillKey.generate()
    end

    #
    # Virtual method for setting the key value (used by the encoder) with the key, can be overriden by encoders
    #
    def setKeyVal(keyVal)
    end

    #
    # lightly polymorphic set of keyReg = keyVal instructions
    # TODO: add more methods
    #
    def fillKeyReg_instructions(keyReg, keyVal)
      fillKeyRegs = []

      fillKeyRegs << Rex::Arch::X86.mov_dword(keyReg, keyVal)

      fillKeyRegs
    end

    #
    # Virtual method for getPC stub generation
    #
    def getPCStub(getPCDestReg)
      return ""
    end

    #
    # Virtual method for custom encoding functionality
    # Note that buf is passed through the calling encoder's super() first and hence consists of an encoded body + decoder stub and not direct plaintext
    #
    def encode(buf)
      return buf
    end

  end

  # Plaintext encoder
  class PlaintextArmor < Armor
    def initialize
      super(
        'Name'             => 'Plaintext',  
        'ID'               => 0,             
        'Description'      => 'Plaintext',
        'Author'           => 'Jos Wetzels',   
        'License'          => MSF_LICENSE,   
        'Target'           => '',             
        'SizeIncrease'     => 0,         
        'isGetPC'          => 0,
        'hasEncoder'       => 1,
        'Conflicts'        => [],             
        'PreDeps'          => [],             
        'PostDeps'         => [])             
    end
  end

  # Anti-preprocessing parent class
  class AntiPreProcessArmor < Armor
  end

  # Anti-emulation parent class
  class AntiEmulArmor < Armor
  end

  # Anti-heuristics parent class
  class AntiHeuristicArmor < Armor
  end

end
