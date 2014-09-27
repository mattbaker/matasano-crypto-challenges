#!/usr/bin/env ruby
require 'base64'

def hexToB64(hexStr)
  plain_text = hexStr
    .scan(/../)
    .map(&:hex)
    .map(&:chr)
    .join("")
  Base64.strict_encode64(plain_text)
end

if ARGV.length > 0
  puts hexToB64(ARGV[0])
else
  puts "e.x. ruby hex-to-b64.rb 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
end
