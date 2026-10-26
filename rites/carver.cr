require "./common"
require "./cfb"

# embedded-artifact carver: magic-byte sweep across any container
# (OneNote revision stores, unknown blobs, everything the readers
# above could not fully parse). offsets only, nothing is written out
# unless the operator asks.
module Grim::Carver
  record Find, kind : String, offset : Int32, note : String

  SIGS = [
    {"PE executable (MZ)", Bytes[0x4D, 0x5A]},
    {"zip package (PK)", Bytes[0x50, 0x4B, 0x03, 0x04]},
    {"OLE compound file", Grim::Cfb::MAGIC},
    {"PDF document", Bytes[0x25, 0x50, 0x44, 0x46]},
    {"gzip stream", Bytes[0x1F, 0x8B]},
    {"7z archive", Bytes[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]},
    {"rar archive", Bytes[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]},
    {"lnk shortcut", Bytes[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]},
    {"elf binary", Bytes[0x7F, 0x45, 0x4C, 0x46]},
    {"sqlite database", Bytes[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65]},
  ]

  def self.scan(b : Bytes) : Array(Find)
    out = [] of Find
    taken = [] of Range(Int32, Int32)
    per_kind = Hash(String, Int32).new(0)
    SIGS.each do |kind, sig|
      pos = 0
      while (idx = index_of(b, sig, pos))
        pos = idx + 1
        next if pos > b.size - 2
        next if per_kind[kind] >= 8 || out.size >= 64
        # overlap guard: skip finds fully covered by an earlier, more
        # specific signature block
        next if taken.any? { |r| idx >= r.begin && idx < r.end }
        note = note_for(kind, b, idx)
        # MZ noise control: only keep real PE headers, or the very first MZ
        if kind.starts_with?("PE executable")
          if note.includes?("MZ bytes only") && per_kind[kind] > 0
            next
          end
        end
        out << Find.new(kind, idx, note)
        per_kind[kind] += 1
        # treat container starts as claimed territory
        if kind =~ /OLE|zip|7z|rar/
          claim_end = Math.min(idx + (1 << 10), b.size)
          taken << (idx...claim_end)
        end
      end
    end
    out.sort_by(&.offset)
  end

  private def self.index_of(b : Bytes, sig : Bytes, from : Int) : Int32?
    return nil if from >= b.size || sig.empty?
    last = b.size - sig.size
    i = from
    while i <= last
      j = 0
      match = true
      while j < sig.size
        if b[i + j] != sig[j]
          match = false
          break
        end
        j += 1
      end
      return i.to_i32 if match
      i += 1
    end
    nil
  end

  private def self.note_for(kind : String, b : Bytes, at : Int) : String
    if kind == "OLE compound file" && at + 512 <= b.size
      ssz = 1 << Grim.u16le(b, at + 30)
      "sector size #{ssz}"
    elsif kind == "zip package (PK)"
      "local header"
    elsif kind == "PE executable (MZ)"
      # quick PE lfanew sanity check
      if at + 0x40 <= b.size
        e_lfanew = Grim.u32le(b, at + 0x3C)
        if e_lfanew > 0 && e_lfanew < 0x4000 && at + e_lfanew + 4 <= b.size && b[at + e_lfanew, 4] == Bytes[0x50, 0x45, 0x00, 0x00]
          "valid PE header"
        else
          "MZ bytes only (false positive possible)"
        end
      else
        "MZ bytes only (false positive possible)"
      end
    else
      ""
    end
  end

  # OneNote revision-store probe: header GUID + embedded-string marker
  ONENOTE_GUID = Bytes[0xA7, 0x6E, 0x92, 0x74, 0xC1, 0xD8, 0x4E, 0x41,
                        0xA8, 0xB9, 0xBD, 0xC0, 0xB4, 0xE1, 0x1F, 0x50]

  def self.onenote?(b : Bytes) : Bool
    return true if b.size >= 16 && b[0, 16] == ONENOTE_GUID
    head = b[0, Math.min(b.size, 8192)]
    needle = "OneNote".to_slice
    return false if head.size < needle.size
    (0..head.size - needle.size).each do |i|
      return true if head[i, needle.size] == needle
    end
    false
  end
end
