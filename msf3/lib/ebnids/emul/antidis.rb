# -*- coding: binary -*-

# =============================================================
# 'Anti-disassembly' anti-emulation armoring classes
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'ebnids/getpc'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids

  # Anti-emulation class
  class AntiDisArmor < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'Anti-disassembly-based anti-emulation armor',  
        'ID'               => 21,             
        'Description'      => 'Anti-emulation armor integrating anti-disassembly instructions',
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

    def getPCStub(getPCDestReg)
      randomKey = Rex::Text.rand_text(4, @module_metadata['badchars']).unpack('V')[0]
      return Ebnids::GetPCStub.antiDisGetPC(getPCDestReg, @module_metadata['badchars'], randomKey)
    end

  end

end
