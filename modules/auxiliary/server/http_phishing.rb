##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/exceptions'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP relay',
      'Description' => %q{
      Simple HTTP relay
        },
      'Author'      =>
        [
          'timwr',
        ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer'))

    register_options([
      OptBool.new('RSSL', [true, "SSL on the remote connection ", false]),
    ])
  end

  def on_request_uri(cli, request)
    print_status("Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")
    uri = request.uri
    res = send_request_cgi({
      'uri'      => uri,
      'method'   => request.method,
      'headers'  => request.headers,
    })

    response = create_response(res.code)
    response.body = res.body
    response.headers = res.headers
    cli.send_response(response)
  end

  def run
    exploit
  end

end
