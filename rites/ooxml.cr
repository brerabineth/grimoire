require "./common"
require "compress/zip"
require "xml"
require "./cfb"
require "./vba"
require "./vbascan"

# OOXML package reader: the docx/xlsm/pptx era. a zip of XML parts and
# binary blobs; the interesting ones are templates, relationships, VBA
# project bins, activeX controls, embedded OLE objects and XLM sheets.
module Grim::Ooxml
  class Error < Exception; end

  record Part, name : String, size : Int32, csize : Int32, encrypted : Bool

  record ExtRel, part : String, target : String, rtype : String, attached_template : Bool

  record Field, part : String, instr : String

  record Package,
    parts : Array(Part),
    ext_rels : Array(ExtRel),
    fields : Array(Field),
    vba_parts : Array(String),
    vba_sources : Array(Grim::Vba::Source),
    active_x : Int32,
    embeddings : Array(String),
    macrosheets : Array(String),
    xlm_calls : Array(String),
    update_fields : Bool,
    protected_doc : Bool,
    encrypted_parts : Int32

  def self.match?(b : Bytes) : Bool
    b.size >= 4 && b[0, 2] == Bytes[0x50, 0x4B]
  end

  def self.parse(b : Bytes) : Package
    io = IO::Memory.new(b)
    zip = Compress::Zip::File.new(io)
    parts = [] of Part
    enc = 0
    zip.entries.each do |e|
      next if e.dir?
      encrypted = (e.general_purpose_bit_flag & 1) != 0
      enc += 1 if encrypted
      parts << Part.new(e.filename, e.uncompressed_size.to_i32, e.compressed_size.to_i32, encrypted)
    end

    ext_rels = read_ext_rels(zip, parts)
    fields = read_fields(zip, parts)
    vba_parts = parts.select { |p| p.name.downcase.ends_with?("vbaproject.bin") }.map(&.name)
    vba_sources = [] of Grim::Vba::Source
    vba_parts.each do |vp|
      next unless (entry = zip[vp]?)
      blob = entry_bytes(zip, entry)
      vba_sources.concat(Grim::Vba.extract(blob))
    end
    active_x = parts.count { |p| p.name =~ /activeX\/activeX[^\/]*\.bin$/i }
    embeddings = parts.select { |p| p.name =~ /embeddings\/[^\/]+\.(bin|xlsx?|docx?|pdf|one|emf)$/i }.map(&.name)
    macrosheets = parts.select { |p| p.name =~ /xl\/macrosheets\/[^\/]+\.xml$/i }.map(&.name)

    xlm_calls = [] of String
    macrosheets.each do |ms|
      next unless (entry = zip[ms]?)
      txt = entry_text(zip, entry)
      txt.scan(/(?i)=\s*(EXEC|CALL|REGISTER|FORMULA\.?CONVERT|SET\.?VALUE)\s*\(/) do |m|
        xlm_calls << m[1].upcase
      end
    end

    update_fields = false
    protected_doc = false
    parts.each do |p|
      next unless p.name =~ /(^|\/)settings\.xml$/i
      next unless (entry = zip[p.name]?)
      txt = entry_text(zip, entry)
      update_fields = true if txt =~ /updateFields[^>]*w:val\s*=\s*"(?:true|1)"/i
      protected_doc = true if txt =~ /documentProtection[^>]*w:edit\s*=\s*"(?:readOnly|forms)"/i
    end

    Package.new(parts, ext_rels, fields, vba_parts, vba_sources, active_x,
      embeddings, macrosheets, xlm_calls, update_fields, protected_doc, enc)
  end

  private def self.entry_bytes(zip : Compress::Zip::File, entry : Compress::Zip::File::Entry) : Bytes
    entry.open do |io|
      io.gets_to_end.to_slice
    end
  rescue
    Bytes.empty
  end

  private def self.entry_text(zip : Compress::Zip::File, entry : Compress::Zip::File::Entry) : String
    entry.open do |io|
      io.gets_to_end
    end
  rescue
    ""
  end

  private def self.read_ext_rels(zip : Compress::Zip::File, parts : Array(Part)) : Array(ExtRel)
    out = [] of ExtRel
    parts.each do |p|
      next unless p.name =~ /_rels\/[^\/]+\.rels$/i
      next unless (entry = zip[p.name]?)
      txt = entry_text(zip, entry)
      next if txt.empty?
      begin
        doc = XML.parse(txt, options: XML::ParserOptions::RECOVER)
      rescue
        next
      end
      owner = p.name.sub(/_rels\//, "").sub(/\.rels$/i, "")
      doc.xpath_nodes("//*[local-name()='Relationship']").each do |n|
        mode = n["TargetMode"]? || ""
        next unless mode.downcase == "external"
        target = n["Target"]? || ""
        rtype = n["Type"]? || ""
        next if target.empty?
        attached = !!(rtype.downcase.includes?("attachedtemplate") ||
                      (owner =~ /settings\.xml$/i && target =~ /^(https?|file|ftp|\\\\)/i))
        out << ExtRel.new(owner, target, rtype, attached)
      end
    end
    out.uniq { |r| "#{r.part}|#{r.target}" }
  end

  private def self.read_fields(zip : Compress::Zip::File, parts : Array(Part)) : Array(Field)
    out = [] of Field
    parts.each do |p|
      next unless p.name =~ /\.(xml)$/i && p.name !~ /_rels\//
      next unless (entry = zip[p.name]?)
      txt = entry_text(zip, entry)
      next if txt.empty? || txt.size > 24_000_000
      # field instructions live in w:instrText / w:fldSimple[@w:instr]
      txt.scan(/(?i)<(?:\w+:)?instrText[^>]*>([^<]{1,4096})<\/(?:\w+:)?instrText>/) do |m|
        instr = m[1].strip
        out << Field.new(p.name, instr) unless instr.empty?
      end
      txt.scan(/(?i)<(?:\w+:)?fldSimple[^>]*w:instr\s*=\s*"([^"]{1,4096})"/) do |m|
        instr = m[1].strip
        out << Field.new(p.name, instr) unless instr.empty?
      end
    end
    out.uniq { |f| "#{f.part}|#{f.instr}" }
  end
end
