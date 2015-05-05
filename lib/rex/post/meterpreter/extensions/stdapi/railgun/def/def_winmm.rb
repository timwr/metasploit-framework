# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_winmm

  def self.create_dll(dll_path = 'winmm')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('mciSendStringA', 'DWORD', [
      %w(PCHAR lpszCommand in),
      %w(DWORD lpszReturnString out),
      %w(DWORD cchReturn out)
      %w(HANDLE hwndCallback in)
    ])

    dll.add_function('mciSendStringW', 'DWORD', [
      %w(PWCHAR lpszCommand in),
      %w(DWORD lpszReturnString out),
      %w(DWORD cchReturn out)
      %w(HANDLE hwndCallback in)
    ])

    return dll
  end

end

end; end; end; end; end; end; end
