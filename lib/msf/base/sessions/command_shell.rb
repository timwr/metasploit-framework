# -*- coding: binary -*-
require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'shellwords'
require 'rex/text/table'


module Msf
module Sessions

###
#
# This class provides basic interaction with a command shell on the remote
# endpoint.  This session is initialized with a stream that will be used
# as the pipe for reading and writing the command shell.
#
###
class CommandShell

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  #
  # This interface supports interacting with a single command shell.
  #
  include Msf::Session::Provider::SingleCommandShell

  include Msf::Session::Scriptable

  include Rex::Ui::Text::Resource

  ##
  # :category: Msf::Session::Scriptable implementors
  #
  # Executes the supplied script, must be specified as full path.
  #
  # Msf::Session::Scriptable implementor
  #
  def execute_file(full_path, args)
    o = Rex::Script::Shell.new(self, full_path)
    o.run(args)
  end

  #
  # Returns the type of session.
  #
  def self.type
    "shell"
  end

  def initialize(conn, opts = {})
    self.platform ||= ""
    self.arch     ||= ""
    self.max_threads = 1
    datastore = opts[:datastore]
    if datastore && !datastore["CommandShellCleanupCommand"].blank?
      @cleanup_command = opts[:datastore]["CommandShellCleanupCommand"]
    end
    super
  end

  #
  # Returns the session description.
  #
  def desc
    "Command shell"
  end

  #
  # List of supported commands.
  #
  def commands
    {
        'help'         =>  'Help menu',
        'background'   => 'Backgrounds the current shell session',
        'sessions'     => 'Quickly switch to another session',
        'resource'     => 'Run the commands stored in a file',
    }
  end

  #
  # Parse a line into an array of arguments.
  #
  def parse_line(line)
    line.split(' ')
  end

  #
  # Explicitly runs a command.
  #
  def run_cmd(cmd)
    # Do nil check for cmd (CTRL+D will cause nil error)
    return unless cmd

    arguments = parse_line(cmd)
    method    = arguments.shift

    # Built-in command
    if commands.key?(method)
      return run_command(method, arguments)
    end

    # User input is not a built-in command, write to socket directly
    shell_write(cmd)
  end

  def cmd_help(*args)
    columns = ['Command', 'Description']
    tbl = Rex::Text::Table.new(
      'Header'  => 'Meta shell commands',
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Indent'  => 4,
      'Columns' => columns,
      'SortIndex' => -1
    )
    commands.each do |key, value|
      tbl << [key, value]
    end
    print(tbl.to_s)
  end

  def cmd_background_help
    print_line "Usage: background"
    print_line
    print_line "Stop interacting with this session and return to the parent prompt"
    print_line
  end

  def cmd_background(*args)
    if !args.empty?
      # We assume that background does not need arguments
      # If user input does not follow this specification
      # Then show help (Including '-h' '--help'...)
      return cmd_background_help
    end

    if prompt_yesno("Background session #{name}?")
      self.interacting = false
    end
  end

  def cmd_sessions_help
    print_line('Usage: sessions <id>')
    print_line
    print_line('Interact with a different session Id.')
    print_line('This command only accepts one positive numeric argument.')
    print_line('This works the same as calling this from the MSF shell: sessions -i <session id>')
    print_line
  end

  def cmd_sessions(*args)
    if args.length.zero? || args[0].to_i <= 0
      # No args
      return cmd_sessions_help
    end

    if args.length == 1 && (args[1] == '-h' || args[1] == 'help')
      # One arg, and args[1] => '-h' '-H' 'help'
      return cmd_sessions_help
    end

    if args.length != 1
      # More than one argument
      return cmd_sessions_help
    end

    if args[0].to_s == self.name.to_s
      # Src == Dst
      print_status("Session #{self.name} is already interactive.")
    else
      print_status("Backgrounding session #{self.name}...")
      # store the next session id so that it can be referenced as soon
      # as this session is no longer interacting
      self.next_session = args[0]
      self.interacting = false
    end
  end

  def cmd_resource(*args)
    if args.empty?
      cmd_resource_help
      return false
    end

    args.each do |res|
      good_res = nil
      if res == '-'
        good_res = res
      elsif ::File.exist?(res)
        good_res = res
      elsif
        # let's check to see if it's in the scripts/resource dir (like when tab completed)
      [
          ::Msf::Config.script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
          ::Msf::Config.user_script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter'
      ].each do |dir|
        res_path = ::File::join(dir, res)
        if ::File.exist?(res_path)
          good_res = res_path
          break
        end
      end
      end
      if good_res
        load_resource(good_res)
      else
        print_error("#{res} is not a valid resource file")
        next
      end
    end
  end

  def cmd_resource_help
    print_line "Usage: resource path1 [path2 ...]"
    print_line
    print_line "Run the commands stored in the supplied files (- for stdin)."
    print_line "Resource files may also contain ERB or Ruby code between <ruby></ruby> tags."
    print_line
  end

  #
  # Run built-in command
  #
  def run_command(method, arguments)
    # Dynamic function call
    self.send('cmd_' + method, *arguments)
  end

  #
  # Calls the class method.
  #
  def type
    self.class.type
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # The shell will have been initialized by default.
  #
  def shell_init
    return true
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Explicitly run a single command, return the output.
  #
  def shell_command(cmd)
    # Send the command to the session's stdin.
    shell_write(cmd + "\n")

    timeo = 5
    etime = ::Time.now.to_f + timeo
    buff = ""

    # Keep reading data until no more data is available or the timeout is
    # reached.
    while (::Time.now.to_f < etime and (self.respond_to?(:ring) or ::IO.select([rstream], nil, nil, timeo)))
      res = shell_read(-1, 0.01)
      buff << res if res
      timeo = etime - ::Time.now.to_f
    end

    buff
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Read from the command shell.
  #
  def shell_read(length=-1, timeout=1)
    return shell_read_ring(length,timeout) if self.respond_to?(:ring)

    begin
      rv = rstream.get_once(length, timeout)
      framework.events.on_session_output(self, rv) if rv
      return rv
    rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      #print_error("Socket error: #{e.class}: #{e}")
      shell_close
      raise e
    end
  end

  #
  # Read from the command shell.
  #
  def shell_read_ring(length=-1, timeout=1)
    self.ring_buff ||= ""

    # Short-circuit bad length values
    return "" if length == 0

    # Return data from the stored buffer if available
    if self.ring_buff.length >= length and length > 0
      buff = self.ring_buff.slice!(0,length)
      return buff
    end

    buff = self.ring_buff
    self.ring_buff = ""

    begin
      ::Timeout.timeout(timeout) do
        while( (length > 0 and buff.length < length) or (length == -1 and buff.length == 0))
          ring.select
          nseq,data = ring.read_data(self.ring_seq)
          if data
            self.ring_seq = nseq
            buff << data
          end
        end
      end
    rescue ::Timeout::Error
    rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      shell_close
      raise e
    end

    # Store any leftovers in the ring buffer backlog
    if length > 0 and buff.length > length
      self.ring_buff = buff[length, buff.length - length]
      buff = buff[0,length]
    end

    buff
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Writes to the command shell.
  #
  def shell_write(buf)
    return unless buf

    begin
      framework.events.on_session_command(self, buf.strip)
      rstream.write(buf)
    rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      #print_error("Socket error: #{e.class}: #{e}")
      shell_close
      raise e
    end
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Closes the shell.
  # Note: parent's 'self.kill' method calls cleanup below.
  #
  def shell_close()
    self.kill
  end

  ##
  # :category: Msf::Session implementors
  #
  # Closes the shell.
  #
  def cleanup
    if rstream
      if !@cleanup_command.blank?
        shell_command_token(@cleanup_command, 0)
      end
      rstream.close
      rstream = nil
    end
    super
  end

  #
  # Execute any specified auto-run scripts for this session
  #
  def process_autoruns(datastore)
    # Read the initial output and mash it into a single line
    if (not self.info or self.info.empty?)
      initial_output = shell_read(-1, 0.01)
      if (initial_output)
        initial_output.force_encoding("ASCII-8BIT") if initial_output.respond_to?(:force_encoding)
        initial_output.gsub!(/[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]+/n,"_")
        initial_output.gsub!(/[\r\n\t]+/, ' ')
        initial_output.strip!

        # Set the inital output to .info
        self.info = initial_output
      end
    end

    if datastore['InitialAutoRunScript'] && !datastore['InitialAutoRunScript'].empty?
      args = Shellwords.shellwords( datastore['InitialAutoRunScript'] )
      print_status("Session ID #{sid} (#{tunnel_to_s}) processing InitialAutoRunScript '#{datastore['InitialAutoRunScript']}'")
      execute_script(args.shift, *args)
    end

    if (datastore['AutoRunScript'] && datastore['AutoRunScript'].empty? == false)
      args = Shellwords.shellwords( datastore['AutoRunScript'] )
      print_status("Session ID #{sid} (#{tunnel_to_s}) processing AutoRunScript '#{datastore['AutoRunScript']}'")
      execute_script(args.shift, *args)
    end
  end

  def reset_ring_sequence
    self.ring_seq = 0
  end

  attr_accessor :arch
  attr_accessor :platform
  attr_accessor :max_threads

protected

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    framework.events.on_session_interact(self)
    if self.respond_to?(:ring)
      _interact_ring
    else
      _interact_stream
    end
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    fds = [rstream.fd, user_input.fd]
    while self.interacting
      sd = Rex::ThreadSafe.select(fds, nil, fds, 0.5)
      next unless sd

      if sd[0].include? rstream.fd
        user_output.print(shell_read)
      end
      if sd[0].include? user_input.fd
        shell_write(user_input.gets)
      end
      Thread.pass
    end
  end

  def _interact_ring

    begin

    rdr = framework.threads.spawn("RingMonitor", false) do
      seq = nil
      while self.interacting

        # Look for any pending data from the remote ring
        nseq,data = ring.read_data(seq)

        # Update the sequence number if necessary
        seq = nseq || seq

        # Write output to the local stream if successful
        user_output.print(data) if data

        begin
          # Wait for new data to arrive on this session
          ring.wait(seq)
        rescue EOFError => e
          break
        end
      end
    end

    while self.interacting
      # Look for any pending input or errors from the local stream
      sd = Rex::ThreadSafe.select([ _local_fd ], nil, [_local_fd], 5.0)

      # Write input to the ring's input mechanism
      run_cmd(user_input.gets) if sd
    end

    ensure
      rdr.kill
    end
  end

  attr_accessor :ring_seq    # This tracks the last seen ring buffer sequence (for shell_read)
  attr_accessor :ring_buff   # This tracks left over read data to maintain a compatible API
end

class CommandShellWindows < CommandShell
  def initialize(*args)
    self.platform = "windows"
    super
  end
  def shell_command_token(cmd,timeout = 10)
    shell_command_token_win32(cmd,timeout)
  end
end

class CommandShellUnix < CommandShell
  def initialize(*args)
    self.platform = "unix"
    super
  end
  def shell_command_token(cmd,timeout = 10)
    shell_command_token_unix(cmd,timeout)
  end
end

end
end
