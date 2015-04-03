require 'openssl'

module Matasano
  extend self

  #http://www.macfreek.nl/memory/Letter_Distribution
  #Wanted distributions that include frequency of spaces
  LETTER_FREQ = {
    " " => 0.1831685753,
    "e" => 0.1026665037,
    "t" => 0.0751699827,
    "a" => 0.0653216702,
    "o" => 0.0615957725,
    "n" => 0.0571201113,
    "i" => 0.0566844326,
    "s" => 0.0531700534,
    "r" => 0.0498790855,
    "h" => 0.0497856396,
    "l" => 0.0331754796,
    "d" => 0.0328292310,
    "u" => 0.0227579536,
    "c" => 0.0223367596,
    "m" => 0.0202656783,
    "f" => 0.0198306716,
    "w" => 0.0170389377,
    "g" => 0.0162490441,
    "p" => 0.0150432428,
    "y" => 0.0142766662,
    "b" => 0.0125888074,
    "v" => 0.0079611644,
    "k" => 0.0056096272,
    "x" => 0.0014092016,
    "j" => 0.0009752181,
    "q" => 0.0008367550,
    "z" => 0.0005128469
  }

  def str_to_bytes(str)
    str.chars.map(&:ord)
  end

  def bytes_to_str(arr)
    arr.map(&:chr).join("")
  end

  def hex_str_to_bytes(str)
    str.scan(/../).map(&:hex)
  end

  def bytes_to_hex_str(arr)
    arr.map{|byte| byte.to_s(16).rjust(2, "0")}.join("")
  end

  def xor_bytes(ar1, ar2)
    ar1.zip(ar2)
      .map{|pair| pair[0] ^ pair[1]}
  end

  def freq_score(str, freqs=LETTER_FREQ)
    str = str.downcase
    freqs.keys.reduce(0) do |score, char|
      delta = (freqs[char] - letter_freq(char, str)).abs
      score + delta
    end
  end

  def letter_freq(char, str)
    (str.count(char) / str.length.to_f)
  end

  def full_key(key, full_length)
    (key * (full_length / key.length)) + key[0 ... full_length % key.length]
  end

  def pad_blocks_to_size(arr, length, fill=0)
    arr.map{|sub_arr| sub_arr.dup.fill(fill, sub_arr.length..length-1)}
  end

  def encrypt_xor(plain_bytes, key_bytes)
    xor_bytes(
      plain_bytes,
      full_key(
        key_bytes,
        plain_bytes.length))
  end

  def decrypt_xor(cipher_bytes, key)
    Matasano::bytes_to_str(
      Matasano::xor_bytes(
        cipher_bytes,
        Matasano.full_key(
          key,
          cipher_bytes.length)))
  end

  def strip_non_printable(str)
    str.gsub(/[^[:print:]]/, '')
  end

  def brute_xor(cipher_bytes, num_candidates=10)
    (0..255).map {|char|
      [char, Matasano.decrypt_xor(cipher_bytes, [char])]
    }
    .map{|char, plain| [char, strip_non_printable(plain)]}
    .reject{|_, plain| plain.empty?}
    .sort_by{|_, plain| freq_score(plain)}
    .take(num_candidates)
  end

  def ham(a,b)
    v = (a ^ b)
    c = 0
    while v > 0
      c += v & 1
      v >>= 1
    end
    c
  end

  def ham_sandwich(byte_ar1, byte_ar2)
    byte_ar1
      .zip(byte_ar2)
      .map{|pair| ham(pair[0], pair[1])}
  end

  def hamming_distance(byte_ar1, byte_ar2)
    ham_sandwich(byte_ar1, byte_ar2).reduce(:+)
  end

  def hamming_difference(chunk_size, bytes, samples = 2)
    chunk_1 = bytes[0...chunk_size]

    bytes[chunk_size..-1]
      .each_slice(chunk_size)
      .take(samples)
      .map {|chunk_2| Matasano::hamming_distance(chunk_1, chunk_2)/chunk_size.to_f }
      .reduce(:+) / samples
  end

  def decrypt_aes_128_ecb(bytes, key)
    data = bytes_to_str(bytes)
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.decrypt
    cipher.padding = 0
    cipher.key = key
    str_to_bytes(cipher.update(data) + cipher.final)
  end

  def encrypt_aes_128_ecb(bytes, key)
    data = bytes_to_str(bytes)
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.encrypt
    cipher.padding = 0
    cipher.key = key
    str_to_bytes(cipher.update(data) + cipher.final)
  end

  def pad_pkcs7(bytes, size)
    fill_length = size - bytes.length
    bytes.dup.fill(fill_length, bytes.length..size-1)
  end

  def encrypt_aes_128_cbc(bytes, key, iv=Array.new(16, 0))
    blocks = bytes.each_slice(16).to_a

    chained = [Matasano.encrypt_aes_128_ecb(Matasano.xor_bytes(blocks.shift, iv), key)]

    blocks.each do |block|
      chained << Matasano.encrypt_aes_128_ecb(Matasano.xor_bytes(block, chained[-1]), key)
    end

    chained.flatten
  end

  def decrypt_aes_128_cbc(bytes, key, iv=Array.new(16, 0))
    (iv + bytes)
      .each_slice(16)
      .each_cons(2)
      .map do |last, current|
        Matasano.xor_bytes(Matasano.decrypt_aes_128_ecb(current, key), last)
      end
      .flatten
  end
end
