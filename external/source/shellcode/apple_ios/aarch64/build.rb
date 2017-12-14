#!/usr/bin/env ruby
# -*- coding: binary -*-

prefix="aarch64-linux-gnu"
filename="stager_sock_reverse"

`#{prefix}-as #{filename}.s -o #{filename}.o`
`#{prefix}-objcopy -O binary #{filename}.o #{filename}.bin`
`#{prefix}-objdump -d #{filename}.o > #{filename}.objdump`

objdump_output = File.open("#{filename}.objdump")
for line in objdump_output.each
  hex_start = line.index(":")
  if hex_start == 4
    hex_data = line[hex_start+2,8]
    asm_comment = line[hex_start+12..-1]
    puts "            0x#{hex_data},          #  #{asm_comment}"
  end
end
