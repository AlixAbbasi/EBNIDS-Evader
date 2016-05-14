##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

module Metasploit3

  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'NOP',
      'Description'   => 'Test NOP',
      'Author'        => [ 'Jos Wetzels' ],
      'License'       => MSF_LICENSE,
      'Platform'      => '',
      'Arch'          => ARCH_X86,
      'Payload'       =>
        {
          'Payload' => "\x90\x90\x90\x90\x90"
        }
      ))
  end

end
