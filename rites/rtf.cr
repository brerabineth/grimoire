require "./common"
require "./cfb"

# RTF reader: the format that refuses to die. control words, field codes
# (DDE/DDEAUTO), embedded objects (\objdata hex -> OLE), remote templates
# ({\*\template}) and the Equation.3 exploit pattern.
module Grim::Rtf
  record ObjData, offset : Int32, kind : String, bytes : Bytes
  record Field, word : String, body : String
  record Scan,
    objdata : Array(ObjData),
    objclass : Array(String),
    fields : Array(Field),
    template : String?,
    objupdate : Bool,
    pict : Int32,
    bin_sizes : Array(Int32),
    max_depth : Int32,
    iocs : Array(Grim::Ioc)

  def self.match?(b : Bytes) : Bool
    b.size >= 5 && (b[0, 5] == Bytes[0x7B, 0x5C, 0x72, 0x74, 0x66]) # "{\rtf"
  end

  def self.parse(b : Bytes) : Scan
    # String.new(b, "UTF-8", invalid: :skip) silently drops bytes even in
    # pure-ASCII data (observed on crystal 1.22); decode raw and scrub instead.
    text = String.new(b).scrub

    objdata = [] of ObjData
    # \objdata followed by hex payload (whitespace tolerated) or \binN binary.
    # manual walk: PCRE2 truncates multi-kilobyte captures, this does not.
    pos = 0
    while (idx = text.index("\\objdata", pos))
      j = idx + 8
      while j < text.size && (text[j].hex? || text[j].whitespace?)
        j += 1
      end
      raw = text[idx + 8, j - idx - 8]
      hex = raw.delete(" \r\n\t")
      if hex.size >= 64
        hex = hex[0, hex.size - (hex.size % 2)]
        blob = hex.hexbytes?
        if blob
          kind = classify(blob)
          objdata << ObjData.new(idx, kind, blob[0, Math.min(blob.size, 1 << 22)])
        end
      end
      pos = j
    end

    objclass = [] of String
    text.scan(/\\(?:\*\\)?objclass\s+([A-Za-z0-9_.\- ]{1,64})/) do |m|
      objclass << m[1].strip
    end

    fields = [] of Field
    # braced instruction group: {\*\fldinst{DDEAUTO "cmd" "/k ..."}}
    text.scan(/\{\\\*\\fldinst\s*\{([^{}]{0,1024})\}/i) do |m|
      body = m[1].strip
      word = body.split(/\s+/)[0]?.to_s.upcase
      next unless word =~ /^(DDEAUTO|DDE)$/
      fields << Field.new(word, body)
    end
    # bare instruction: {\*\fldinst DDEAUTO ...}
    text.scan(/\{\\\*\\fldinst\s+([^{}]{0,1024})/i) do |m|
      body = m[1].strip
      word = body.split(/\s+/)[0]?.to_s.upcase
      next unless word =~ /^(DDEAUTO|DDE)$/
      fields << Field.new(word, body)
    end

    template : String? = nil
    text.scan(/\{\\\*\\template\s+([^{}]{1,512})\}/i) do |m|
      template = m[1].strip
    end

    objupdate = text =~ /\\objupdate/ != nil
    pict = text.scan(/\\pict/).size
    bin_sizes = text.scan(/\\bin(\d+)\b/).map { |m| m[1].to_i }.select { |s| s > 0 }

    max_depth = max_group_depth(text)

    iocs = Grim.iocs(text)

    Scan.new(objdata, objclass.uniq, fields.uniq { |f| f.body }, template,
      objupdate, pict, bin_sizes, max_depth, iocs)
  end

  private def self.classify(blob : Bytes) : String
    if blob.size >= 8 && blob[0, 8] == Grim::Cfb::MAGIC
      "OLE compound file"
    elsif blob.size >= 2 && blob[0, 2] == Bytes[0x4D, 0x5A]
      "PE executable (MZ)"
    elsif blob.size >= 2 && blob[0, 2] == Bytes[0x50, 0x4B]
      "zip package (PK)"
    elsif blob.size >= 4 && blob[0, 4] == Bytes[0x25, 0x50, 0x44, 0x46]
      "PDF document"
    else
      "unknown binary"
    end
  end

  # deepest {\ nesting level — huge depths are a scanner-crash trick
  private def self.max_group_depth(text : String) : Int32
    depth = 0
    max = 0
    text.each_char do |c|
      if c == '{'
        depth += 1
        max = depth if depth > max
      elsif c == '}'
        depth -= 1
      end
      break if depth > 60_000 # hostile; stop counting
    end
    max
  end

  # drill into the first OLE objdata blob: stream names + ole10native + vba probe
  def self.ole_details(scan : Scan) : Array(String)
    out = [] of String
    scan.objdata.each do |od|
      next unless od.bytes.size >= 8 && od.bytes[0, 8] == Grim::Cfb::MAGIC
      begin
        repo = Grim::Cfb::Repo.new(od.bytes)
        names = repo.streams.map(&.name)
        out << names.map { |n| n.starts_with?("\u0005") ? "##{n[1, n.size - 1]}" : n }.join(", ")
        if (nat = repo.stream_named("\u0001Ole10Native"))
          if (pair = Grim::Cfb.ole10native(nat))
            out << "Ole10Native embedded file: #{pair[0]} (#{pair[1]})"
          end
        end
        repo.streams.each do |s|
          if s.name.downcase == "vbaproject.bin"
            out << "vbaProject.bin inside RTF object"
          end
        end
      rescue Grim::Cfb::Error
        out << "OLE parse failed (truncated objdata)"
      end
    end
    out.uniq
  end
end
