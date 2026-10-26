require "./common"

# Compound File Binary (OLE2) reader — the container under .doc/.xls/.ppt,
# vbaProject.bin, embedded objects and a thousand malware families.
# implements enough of MS-CFB to walk FAT/miniFAT chains and pull streams.
module Grim::Cfb
  MAGIC = Bytes[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]

  class Error < Exception; end

  # utf-16le -> string, stops at the first null terminator
  module U16
    def self.to_s(b : Bytes) : String
      String.build(b.size // 2) do |s|
        i = 0
        while i + 1 < b.size
          cp = b[i].to_u32! | (b[i + 1].to_u32! << 8)
          break if cp == 0
          s << (cp < 0x110000 ? cp.unsafe_chr : '?')
          i += 2
        end
      end
    end
  end

  record DirEntry,
    index : Int32,
    name : String,
    kind : UInt8,          # 0 unknown 1 storage 2 stream 5 root
    start : UInt32,
    size : UInt64,
    clsid : String

  class Repo
    getter entries : Array(DirEntry)
    getter sector_shift : Int32

    @ministream_cache : Bytes?
    @minifat_cache : Array(UInt32)?
    @ssz : Int32 = 512
    @msz : Int32 = 64
    @first_dir : UInt32 = 0
    @mini_cutoff : UInt32 = 4096
    @first_minifat : UInt32 = 0xFFFFFFFE
    @n_minifat : UInt32 = 0
    @first_difat : UInt32 = 0xFFFFFFFE
    @n_difat : UInt32 = 0
    @fat : Array(UInt32) = [] of UInt32

    def initialize(@data : Bytes)
      raise Error.new("not CFB: short header") if @data.size < 512
      raise Error.new("not CFB: bad magic") unless @data[0, 8] == MAGIC
      @sector_shift = Grim.u16le(@data, 30).to_i32
      raise Error.new("not CFB: sector shift #{@sector_shift}") unless @sector_shift == 9 || @sector_shift == 12
      @mini_shift = Grim.u16le(@data, 32).to_i32
      @ssz = 1 << @sector_shift
      @msz = 1 << @mini_shift
      @first_dir = Grim.u32le(@data, 48)
      @mini_cutoff = Grim.u32le(@data, 56)
      @first_minifat = Grim.u32le(@data, 60)
      @n_minifat = Grim.u32le(@data, 64)
      @first_difat = Grim.u32le(@data, 68)
      @n_difat = Grim.u32le(@data, 72)
      @fat = build_fat
      @entries = read_dir
    end

    # ---- sector plumbing -------------------------------------------------

    private def sector(off : UInt32) : Bytes
      base = 512 + off.to_i64 * @ssz
      raise Error.new("sector #{off} out of file (size #{@data.size})") if base < 0 || base + @ssz > @data.size
      @data[base, @ssz]
    end

    private def build_fat : Array(UInt32)
      difat = Array(UInt32).new
      109.times do |i|
        v = Grim.u32le(@data, 76 + i * 4)
        difat << v if v != 0xFFFFFFFF_u32
      end
      cur = @first_difat
      hops = 0
      while cur != 0xFFFFFFFE_u32 && @n_difat > 0
        raise Error.new("DIFAT chain too long") if hops > 65536
        s = sector(cur)
        (@ssz // 4 - 1).times do |i|
          v = Grim.u32le(s, i * 4)
          difat << v if v != 0xFFFFFFFF_u32
        end
        cur = Grim.u32le(s, @ssz - 4)
        hops += 1
      end
      fat = Array(UInt32).new
      difat.each do |fs|
        begin
          s = sector(fs)
        rescue Error
          next
        end
        (@ssz // 4).times { |i| fat << Grim.u32le(s, i * 4) }
      end
      raise Error.new("empty FAT") if fat.empty?
      fat
    end

    private def chain(start : UInt32, limit : Int) : Array(UInt32)
      out = Array(UInt32).new
      cur = start
      seen = Set(UInt32).new
      while cur != 0xFFFFFFFE_u32 && cur != 0xFFFFFFFF_u32
        raise Error.new("FAT chain loop at #{cur}") unless seen.add?(cur)
        out << cur
        raise Error.new("FAT chain too long") if out.size > limit
        cur = @fat.fetch(cur) { raise Error.new("FAT index #{cur} out of range") }
      end
      out
    end

    private def read_chain(start : UInt32, size : UInt64) : Bytes
      secs = chain(start, (size.to_i64 // @ssz + 2) * 2 + 64)
      buf = IO::Memory.new
      secs.each do |s|
        buf.write(sector(s))
      end
      b = buf.to_slice
      return b if size == 0 # 0 = read whole chain (directory walk)
      b[0, Math.min(size.to_i64, b.size)]
    end

    private def ministream : Bytes
      cached = @ministream_cache
      return cached if cached
      root = @entries.find { |e| e.kind == 5 }
      raise Error.new("no root entry") unless root
      computed = read_chain(root.start, root.size)
      @ministream_cache = computed
      computed
    end

    private def minifat : Array(UInt32)
      mf = @minifat_cache
      return mf if mf
      parsed = Array(UInt32).new
      if @n_minifat > 0 && @first_minifat != 0xFFFFFFFE_u32
        mf_raw = read_chain(@first_minifat, @n_minifat.to_u64 * @ssz)
        (mf_raw.size // 4).times { |i| parsed << Grim.u32le(mf_raw, i * 4) }
      end
      @minifat_cache = parsed
      parsed
    end

    # ---- directory --------------------------------------------------------

    private def read_dir : Array(DirEntry)
      raw = read_chain(@first_dir, 0)
      out = Array(DirEntry).new
      n = raw.size // 128
      raise Error.new("directory too large") if n > 100_000
      n.times do |i|
        e = raw[i * 128, 128]
        nlen = Grim.u16le(e, 64)
        next if nlen == 0
        nlen = Math.min(nlen, 64)
        name = begin
          U16.to_s(e[0, nlen])
        rescue
          "?"
        end
        kind = e[66]
        start = Grim.u32le(e, 116)
        size = Grim.u64le(e, 120)
        if @sector_shift == 9
          size = size & 0xFFFFFFFF_u64
        end
        clsid = String.build do |s|
          16.times { |k| s << e[80 + k].to_s(16, upcase: false).rjust(2, '0') }
        end
        out << DirEntry.new(i, name, kind, start, size, clsid)
      end
      out
    end

    # ---- stream access ----------------------------------------------------

    def streams : Array(DirEntry)
      @entries.select { |e| e.kind == 2 }
    end

    def find(name : String) : DirEntry?
      @entries.find { |e| e.name == name }
    end

    def stream(entry : DirEntry) : Bytes
      return Bytes.empty unless entry.kind == 2
      if entry.size < @mini_cutoff
        raw = ministream
        mf = minifat
        buf = IO::Memory.new
        cur = entry.start
        seen = Set(UInt32).new
        hops = 0
        want = ((entry.size.to_i64 + @msz - 1) // @msz)
        while cur != 0xFFFFFFFE_u32 && cur != 0xFFFFFFFF_u32 && hops < 10_000_000
          raise Error.new("mini chain loop at #{cur}") unless seen.add?(cur)
          idx = cur.to_i64 * @msz
          break if idx >= raw.size
          buf.write(raw[idx, Math.min(@msz, raw.size - idx)])
          hops += 1
          break if hops >= want && hops > 0 && mf.empty?
          cur = mf.fetch(cur) { 0xFFFFFFFE_u32 }
          break if hops >= want
        end
        b = buf.to_slice
        b[0, Math.min(entry.size.to_i64, b.size)]
      else
        read_chain(entry.start, entry.size)
      end
    end

    def stream_named(name : String) : Bytes?
      e = find(name)
      e ? stream(e) : nil
    end
  end

  # convenience: is this an OLE file?
  def self.match?(b : Bytes) : Bool
    b.size >= 8 && b[0, 8] == MAGIC
  end

  # property-set (SummaryInformation) reader: title/author/company/template.
  # follows the real PropertySetStream layout: header (26 bytes) then
  # FMTID+offset pairs, then sections of (pid, offset) -> typed values.
  record Meta, pairs : Hash(String, String)

  SUMMARY_FMTID = Bytes[0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10,
                         0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9]

  def self.meta(repo : Repo) : Meta
    pairs = Hash(String, String).new
    {"\u0005SummaryInformation", "\u0005DocumentSummaryInformation"}.each do |sname|
      st = repo.stream_named(sname)
      next unless st
      next unless st.size > 42 && Grim.u16le(st, 0) == 0xFFFE
      nsets = Math.min(Grim.u32le(st, 22).to_i32, 4)
      nsets.times do |s|
        base = 26 + s * 24
        break if base + 24 > st.size
        fmtid = st[base, 16]
        is_summary = fmtid == SUMMARY_FMTID
        off = Grim.u32le(st, base + 16).to_i64
        next unless off > 0 && off + 8 <= st.size
        cprops = Grim.u32le(st, off + 4)
        cprops = Math.min(cprops, 64_u32)
        cprops.times do |i|
          po = off + 8 + i * 8
          break if po + 8 > st.size
          pid = Grim.u32le(st, po)
          voff = off + Grim.u32le(st, po + 4).to_i64
          break if voff + 4 > st.size
          vtype = Grim.u32le(st, voff)
          next unless vtype == 0x1E || vtype == 0x1F
          vlen = Grim.u32le(st, voff + 4)
          next unless vlen > 0 && vlen <= 4096
          avail = st.size - voff - 8
          break if avail <= 0
          raw = st[voff + 8, Math.min(vlen, avail)]
          label = case pid
                  when 2  then "title"
                  when 3  then "subject"
                  when 4  then "author"
                  when 15 then "company"
                  when 12 then "last_saved_by"
                  when 18 then "template"
                  when 13 then "comments"
                  else         nil
                  end
          next unless label
          val = vtype == 0x1F ? U16.to_s(raw) : Grim.cp1252(raw)
          val = val.chomp("\u0000").strip
          pairs[label] = val unless val.empty?
        end
      end
    end
    Meta.new(pairs)
  end

  # \1Ole10Native: first null-terminated string is the embedded file's display
  # name, the second its source path — one of the oldest lies in the format.
  def self.ole10native(st : Bytes) : {String, String}?
    return nil if st.size < 4
    size = Grim.u32le(st, 0)
    return nil unless size > 4 && size <= st.size
    body = st[4, size - 4]
    nul = [] of Int32
    body.each_with_index do |x, i|
      nul << i if x == 0
      break if nul.size == 2
    end
    return nil if nul.empty? || nul[0] == 0
    name = Grim.cp1252(body[0, nul[0]])
    path = nul.size > 1 && nul[1] > nul[0] + 1 ? Grim.cp1252(body[nul[0] + 1, nul[1] - nul[0] - 1]) : ""
    {name, path}
  end
end
