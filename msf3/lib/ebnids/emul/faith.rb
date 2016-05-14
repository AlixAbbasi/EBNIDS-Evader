# -*- coding: binary -*-

# =============================================================
# 'Faithfulness gap' anti-emulation armoring classes
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
  class FaithArmor_FPU < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'FPU-based "Faithfulness gap" anti-emulation armor',  
        'ID'               => 9,             
        'Description'      => 'Anti-emulation armor integrating unsupported FPU instructions',
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
      return Ebnids::GetPCStub.fpuGetPC(getPCDestReg, @module_metadata['badchars'])
    end

  end

  # Anti-emulation class
  class FaithArmor_MMX < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'MMX-based "Faithfulness gap" anti-emulation armor',  
        'ID'               => 10,             
        'Description'      => 'Anti-emulation armor integrating unsupported MMX instructions',
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
      return Ebnids::GetPCStub.mmxGetPC(getPCDestReg, @module_metadata['badchars'])
    end

  end

  # Anti-emulation class
  class FaithArmor_SSE < AntiEmulArmor

    def initialize
      super(
        'Name'             => 'SSE-based "Faithfulness gap" anti-emulation armor',  
        'ID'               => 11,             
        'Description'      => 'Anti-emulation armor integrating unsupported SSE instructions',
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
      return Ebnids::GetPCStub.sseGetPC(getPCDestReg, @module_metadata['badchars'])
    end

  end


  # Anti-emulation class
  class FaithArmor_OBSOL < AntiEmulArmor

    def initialize
      super(
        'Name'             => '"obsolete instruction"-based "Faithfulness gap" anti-emulation armor',  
        'ID'               => 12,             
        'Description'      => 'Anti-emulation armor integrating unsupported "obsolete" instructions',
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
      return Ebnids::GetPCStub.obsolGetPC(getPCDestReg, @module_metadata['badchars'])
    end

  end


end
