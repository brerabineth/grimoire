require "./common"
require "./cfb"

# VBA extraction: MS-OVBA compressed container decoder, dir-stream parser,
# module source recovery. pure byte surgery, nothing runs.
module Grim::Vba
  class Error < Exception; end

  # MS-OVBA 2.4.1 decompressor.
  # container = 0x01 signature byte, then a list of chunks.
  # chunk header u16: bits 0-11 = (chunk size - 3), bits 12-14 = 0b011,
  # bit 15 = 1 compressed / 0 raw. compressed chunks carry flag bytes whose
  # bits alternate literal byte / copy token; copy token split depends on
  # the current decompressed offset inside the 4096-byte history window.
  def self.decompress(b : Bytes) : Bytes?
    return nil if b.size < 3
    return nil unless b[0] == 0x01
    out_io = IO::Memory.new
    pos = 1
    while pos + 1 < b.size
      hdr = Grim.u16le(b, pos)
      pos += 2
      return nil if ((hdr >> 12) & 0x7) != 0b011
      size = (hdr & 0x0FFF) + 3
      compressed = (hdr & 0x8000) != 0
      avail = b.size - pos
      chunk = b[pos, Math.min(size - 2, avail)] # size includes the 2-byte header
      pos += chunk.size
      if !compressed
        out_io.write(chunk[0, Math.min(4096, chunk.size)])
      else
        return nil unless decode_chunk(chunk, out_io)
      end
      break if chunk.size < size - 2
    end
    out_io.to_slice
  end

  private def self.decode_chunk(chunk : Bytes, out_io : IO::Memory) : Bool
    win = Bytes.new(4096)
    win_fill = 0
    chunk_start = out_io.pos
    pos = 0
    while pos < chunk.size
      flags = chunk[pos]
      pos += 1
      8.times do |bit|
        break if pos >= chunk.size
        if (flags & (1 << bit)) == 0
          c = chunk[pos]
          pos += 1
          out_io.write_byte(c)
          win[win_fill % 4096] = c
          win_fill += 1
        else
          # MS-OVBA 2.4.1.3.5: bitcount grows with the decompressed position
          # inside the current chunk; length lives in the low bits, offset in
          # the high bits of the 16-bit copy token.
          pin = out_io.pos - chunk_start
          bitcount = if pin < 16
                       4
                     elsif pin < 32
                       5
                     elsif pin < 64
                       6
                     elsif pin < 128
                       7
                     elsif pin < 256
                       8
                     elsif pin < 512
                       9
                     elsif pin < 1024
                       10
                     elsif pin < 2048
                       11
                     elsif pin < 4096
                       12
                     else
                       13
                     end
          length_mask = 0xFFFF >> bitcount
          offset_mask = ~length_mask & 0xFFFF
          return true if pos + 2 > chunk.size
          tok = chunk[pos].to_u16! | (chunk[pos + 1].to_u16! << 8)
          pos += 2
          length = (tok & length_mask) + 3
          offset = ((tok & offset_mask) >> (16 - bitcount)) + 1
          src = win_fill - offset
          return false if src < 0
          room = 4096 - pin
          len = Math.min(length, room)
          return false if len <= 0
          len.times do |k|
            c = win[(src + k) % 4096]
            out_io.write_byte(c)
            win[win_fill % 4096] = c
            win_fill += 1
          end
        end
      end
    end
    true
  end

  # ---- dir stream -------------------------------------------------------

  record ModuleInfo,
    name : String,
    stream_name : String,
    offset : Int64,
    procedural : Bool

  record ProjectInfo,
    codepage : UInt32,
    modules : Array(ModuleInfo)

  # walk TLV records; ids we care about:
  # 0x0003 codepage, 0x0019 module name, 0x001A module stream name,
  # 0x0031 module text offset, 0x0021 procedural, 0x0022 document/class,
  # 0x002B module terminator, 0x000F end of project
  def self.parse_dir(raw : Bytes) : ProjectInfo?
    return nil if raw.size < 8
    codepage = 1252_u32
    modules = [] of ModuleInfo
    cur : {String, String, Int64, Bool}? = nil
    done_modules = false
    pos = 0
    hops = 0
    while pos + 6 <= raw.size && hops < 10_000
      hops += 1
      id = Grim.u16le(raw, pos)
      size = Grim.u32le(raw, pos + 2)
      body = pos + 6
      if size > raw.size - body
        # malformed tail; bail with what we have
        break
      end
      case id
      when 0x0003
        codepage = Grim.u16le(raw, body).to_u32 if size >= 2
      when 0x0019
        cur = {str(raw[body, size], codepage), "", 0_i64, false}
      when 0x001A, 0x0032
        if (c = cur)
          cur = {c[0], str(raw[body, size], codepage), c[2], c[3]}
        end
      when 0x0031
        if (c = cur) && size >= 4
          cur = {c[0], c[1], Grim.u32le(raw, body).to_i64, c[3]}
        end
      when 0x0021
        if (c = cur)
          cur = {c[0], c[1], c[2], true}
        end
      when 0x0022
        if (c = cur)
          cur = {c[0], c[1], c[2], false}
        end
      when 0x002B
        if (c = cur)
          modules << ModuleInfo.new(c[0], c[1].empty? ? c[0] : c[1], c[2], c[3])
        end
        cur = nil
      when 0x000F
        done_modules = true
      end
      pos = body + size
    end
    if modules.empty? && !done_modules
      return nil
    end
    ProjectInfo.new(codepage, modules)
  end

  private def self.str(b : Bytes, codepage : UInt32) : String
    if codepage == 65001
      String.new(b)
    else
      Grim.cp1252(b)
    end
  end

  # ---- project container ------------------------------------------------

  record Source, name : String, code : String, procedural : Bool

  # pull macro source out of a vbaProject.bin blob
  def self.extract(blob : Bytes) : Array(Source)
    repo = Grim::Cfb::Repo.new(blob)
    dir = repo.stream_named("dir")
    dir ||= begin
      e = repo.find("VBA/dir") || repo.entries.find { |x| x.kind == 2 && x.name.downcase == "dir" }
      e ? repo.stream(e) : nil
    end
    return [] of Source unless dir
    # dir stream is itself a compressed container
    plain = decompress(dir) || dir
    info = parse_dir(plain)
    return [] of Source unless info
    out = [] of Source
    info.modules.each do |m|
      st = repo.stream_named(m.stream_name) ||
           repo.stream_named("VBA/#{m.stream_name}") ||
           repo.stream_named("#{m.stream_name}")
      next unless st
      off = m.offset
      next if off >= st.size
      src = decompress(st[off..]) || begin
        # some generators store plain text
        st[off..]
      end
      next unless src
      out << Source.new(m.name, Grim.cp1252(src), m.procedural)
    end
    out
  rescue Grim::Cfb::Error
    [] of Source
  end
end
