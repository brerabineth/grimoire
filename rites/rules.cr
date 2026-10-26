require "./common"
require "./cfb"
require "./vba"
require "./vbascan"
require "./ooxml"
require "./rtf"
require "./carver"

# verdict engine: turn raw scan surfaces into a severity-scored finding set,
# then a band (clean / watch / suspicious / hostile) and an exit code.
module Grim::Rules
  record Finding, id : String, title : String, sev : Int32, detail : String

  record Verdict,
    score : Int32,
    band : String,
    force : Bool,
    findings : Array(Finding)

  BAND_EXIT = {"clean" => 0, "watch" => 1, "suspicious" => 3, "hostile" => 10}

  def self.band_for(score : Int32, force : Bool) : String
    return "hostile" if force
    if score < 10
      "clean"
    elsif score < 25
      "watch"
    elsif score < 60
      "suspicious"
    else
      "hostile"
    end
  end

  def self.score(findings : Array(Finding)) : {Int32, Bool}
    s = 0
    force = false
    seen = Hash(String, Bool).new
    findings.each do |f|
      next if seen[f.id]?
      seen[f.id] = true
      add = f.sev * 6
      add = Math.min(add, 24)
      s += add
      force = true if FORCE_HOSTILE.includes?(f.id)
    end
    {Math.min(s, 100), force}
  end

  FORCE_HOSTILE = [
    "vba.autoexec.downloader",
    "rtf.equation.exploit",
    "ole.native.executable",
    "doc.dde.executes",
    "vba.proc.inject",
    "xlm.exec.spell",
  ]

  # what got recognized
  record Doc,
    kind : String,             # ooxml / ole / rtf / onenote / zip / unknown / error
    size : Int32,
    sha256 : String,
    package : Grim::Ooxml::Package?,
    ole : Grim::Cfb::Repo?,
    meta : Hash(String, String),
    ole_streams : Array(String),
    ole10native : {String, String}?,
    rtf : Grim::Rtf::Scan?,
    rtf_ole : Array(String),
    carves : Array(Grim::Carver::Find),
    onenote : Bool,
    error : String?

  # ---- top entry ---------------------------------------------------------

  def self.build(data : Bytes) : Doc
    sha = OpenSSL::Digest.new("SHA256").update(data).final.hexstring
    if Grim::Ooxml.match?(data)
      begin
        pkg = Grim::Ooxml.parse(data)
        return Doc.new(kind: "ooxml", size: data.size, sha256: sha, package: pkg,
          ole: nil, meta: Hash(String, String).new, ole_streams: [] of String,
          ole10native: nil, rtf: nil, rtf_ole: [] of String,
          carves: Grim::Carver.scan(data), onenote: false, error: nil)
      rescue e : Exception
        return Doc.new(kind: "error", size: data.size, sha256: sha, package: nil,
          ole: nil, meta: Hash(String, String).new, ole_streams: [] of String,
          ole10native: nil, rtf: nil, rtf_ole: [] of String, carves: [] of Grim::Carver::Find,
          onenote: false, error: "corrupt zip package: #{Grim.clip(e.message || "?", 80)}")
      end
    end
    if Grim::Rtf.match?(data)
      scan = Grim::Rtf.parse(data)
      rtf_ole = Grim::Rtf.ole_details(scan)
      return Doc.new(kind: "rtf", size: data.size, sha256: sha, package: nil,
        ole: nil, meta: Hash(String, String).new, ole_streams: [] of String,
        ole10native: nil, rtf: scan, rtf_ole: rtf_ole,
        carves: Grim::Carver.scan(data), onenote: false, error: nil)
    end
    if Grim::Cfb.match?(data)
      begin
        repo = Grim::Cfb::Repo.new(data)
        meta = Grim::Cfb.meta(repo).pairs
        nat = repo.stream_named("\u0001Ole10Native")
        ole10 = nat ? Grim::Cfb.ole10native(nat) : nil
        streams = repo.streams.map(&.name)
        return Doc.new(kind: "ole", size: data.size, sha256: sha, package: nil,
          ole: repo, meta: meta, ole_streams: streams, ole10native: ole10,
          rtf: nil, rtf_ole: [] of String, carves: Grim::Carver.scan(data),
          onenote: false, error: nil)
      rescue e : Grim::Cfb::Error
        return Doc.new(kind: "error", size: data.size, sha256: sha, package: nil,
          ole: nil, meta: Hash(String, String).new, ole_streams: [] of String,
          ole10native: nil, rtf: nil, rtf_ole: [] of String, carves: [] of Grim::Carver::Find,
          onenote: false, error: "corrupt OLE container: #{Grim.clip(e.message || "?", 80)}")
      end
    end
    on = Grim::Carver.onenote?(data)
    kind = on ? "onenote" : "unknown"
    Doc.new(kind: kind, size: data.size, sha256: sha, package: nil,
      ole: nil, meta: Hash(String, String).new, ole_streams: [] of String,
      ole10native: nil, rtf: nil, rtf_ole: [] of String,
      carves: Grim::Carver.scan(data), onenote: on, error: nil)
  end

  # ---- findings ----------------------------------------------------------

  def self.findings(doc : Doc) : Array(Finding)
    sink = [] of Finding
    if (pkg = doc.package)
      sink.concat(oopackage(doc, pkg))
    end
    if (ole = doc.ole)
      sink.concat(olefile(doc, ole))
    end
    if (rtf = doc.rtf)
      sink.concat(rtffile(doc, rtf))
    end
    sink.concat(container(doc))
    sink
  end

  private def self.push(sink : Array(Finding), id : String, title : String, sev : Int32, detail : String)
    sink << Finding.new(id, title, sev, Grim.mask(Grim.clip(detail)))
  end

  private def self.oopackage(doc : Doc, pkg : Grim::Ooxml::Package) : Array(Finding)
    sink = [] of Finding
    pkg.ext_rels.each do |r|
      scheme = r.target =~ /^(https?|ftp):\/\//i ? "http" : (r.target.starts_with?("\\\\") ? "unc" : (r.target.starts_with?("file:") || r.target.starts_with?("/") ? "file" : "other"))
      if r.attached_template && scheme != "other"
        push(sink, "doc.remote.template", "remote template injection (settings.xml.rels)", 4,
          "#{r.part} fetches #{r.target} on open — classic T1221, the docx itself carries no macro")
      elsif scheme == "http" || scheme == "unc"
        push(sink, "doc.external.link", "external network reference", 2,
          "#{r.part} -> #{r.target}")
      elsif scheme == "file"
        push(sink, "doc.external.file", "external file reference", 1,
          "#{r.part} -> #{r.target}")
      end
    end

    unless pkg.vba_parts.empty?
      push(sink, "vba.project", "VBA project present", 2,
        pkg.vba_parts.join(", "))
    end
    pkg.vba_sources.each do |src|
      an = Grim::VbaScan.analyze(src.code)
      vba_findings(sink, src.name, an)
    end

    if pkg.active_x > 0
      push(sink, "doc.activex", "ActiveX control embedded", 2,
        "#{pkg.active_x} activeX part(s); controls can carry arbitrary script")
    end
    unless pkg.embeddings.empty?
      push(sink, "doc.embedded.objects", "embedded object containers", 2,
        pkg.embeddings.join(", "))
    end
    unless pkg.macrosheets.empty?
      push(sink, "xlm.sheets", "XLM / Excel 4.0 macro sheets", 3,
        pkg.macrosheets.join(", "))
      unless pkg.xlm_calls.empty?
        push(sink, "xlm.exec.spell", "XLM execution calls", 4,
          "#{pkg.xlm_calls.uniq.join(", ")} in #{pkg.macrosheets.size} macro sheet(s)")
      end
    end

    dde = pkg.fields.select { |f| f.instr =~ /(?i)\bDDE(?:AUTO)?\b/ }
    unless dde.empty?
      push(sink, "doc.dde.fields", "DDE field codes", 3, dde.map { |f| f.part }.uniq.join(", "))
      if dde.any? { |f| f.instr =~ /(?i)\b(cmd|powershell|mshta|rundll32|wscript|cscript|regsvr32)\b/ }
        push(sink, "doc.dde.executes", "DDE fields spawn interpreters", 4,
          dde.map { |f| f.instr }.join(" | ")[0, 200])
      end
    end
    if pkg.fields.any? { |f| f.instr =~ /(?i)(INCLUDEPICTURE|LINK)\b.*https?:\/\// }
      push(sink, "doc.fields.remote", "field codes reference remote content", 2, "")
    end

    if pkg.update_fields
      push(sink, "doc.updatefields", "updateFields on open", 2,
        "Word will refresh linked fields at open — used to force remote objects alive")
    end
    if pkg.protected_doc
      push(sink, "doc.protection", "document locked for editing", 1,
        "readOnly/forms protection — keeps victims from touching the lure")
    end
    if pkg.encrypted_parts > 0
      push(sink, "zip.encrypted.parts", "encrypted parts inside package", 3,
        "#{pkg.encrypted_parts} part(s) flag encrypted — classic scanner evasion")
    end
    sink
  end

  def self.vba_findings(sink : Array(Finding), module_name : String, an : Grim::VbaScan::Analysis)
    unless an.triggers.empty?
      push(sink, "vba.autoexec", "auto-execution trigger in #{module_name}", 3,
        an.triggers.join(", "))
    end
    an.hits.each do |h|
      id = "vba.#{h.code}"
      title = {
        "exec"     => "process execution from #{module_name}",
        "net"      => "network fetch from #{module_name}",
        "drop"     => "payload dropping from #{module_name}",
        "persist"  => "persistence markers in #{module_name}",
        "evade"    => "evasion / probing in #{module_name}",
        "proc"     => "native process abuse in #{module_name}",
      }[h.code]? || "suspicious API in #{module_name}"
      push(sink, id, title, h.sev, "#{h.text} x#{h.count}")
    end
    # the combination that matters: trigger + downloader in one module
    if !an.triggers.empty? && an.hits.any? { |h| h.code == "net" } && an.hits.any? { |h| h.code == "exec" || h.code == "drop" }
      push(sink, "vba.autoexec.downloader", "auto-exec + fetch + drop chain", 4,
        "#{module_name} runs on open, downloads and drops")
    end
    if an.hits.any? { |h| h.text == "WriteProcessMemory" || h.text == "VirtualAlloc" || h.text == "RtlMoveMemory" }
      push(sink, "vba.proc.inject", "memory injection primitives", 4,
        "shellcode-style process injection in #{module_name}")
    end
    if an.chr_calls > 24
      push(sink, "vba.obfuscation.chr", "heavy Chr() obfuscation", 2,
        "#{an.chr_calls} Chr/ChrW/ChrB calls in #{module_name}")
    end
    if an.concat_joins > 20
      push(sink, "vba.obfuscation.split", "split string assembly", 1,
        "#{an.concat_joins} line-continuation joins in #{module_name}")
    end
    an.decoded.each do |d|
      next if d.findings.empty? && d.iocs.empty?
      push(sink, "vba.decoded.#{d.kind}", "decoded #{d.kind} payload in #{module_name}", 3,
        d.text[0, 160])
      d.findings.each do |h|
        push(sink, "vba.decoded.hit", "decoded payload wants: #{h.text}", h.sev, "inside #{d.kind} blob")
      end
    end
    if an.entropy > 6.5
      push(sink, "vba.entropy", "high-entropy module body", 1,
        "#{module_name}: #{an.entropy.round(2)} bits/byte")
    end
  end

  private def self.olefile(doc : Doc, repo : Grim::Cfb::Repo) : Array(Finding)
    sink = [] of Finding
    vba_stream = repo.streams.find { |s| s.name.downcase == "vbaproject.bin" }
    if vba_stream
      push(sink, "vba.project", "VBA project present", 2, vba_stream.name)
      blob = repo.stream(vba_stream)
      sources = Grim::Vba.extract(blob)
      sources.each do |src|
        an = Grim::VbaScan.analyze(src.code)
        vba_findings(sink, src.name, an)
      end
    end
    if (nat = doc.ole10native)
      name, path = nat
      if name =~ /\.(exe|scr|pif|bat|cmd|js|vbs|ps1|hta|dll|jar|lnk|iso|img|7z|zip)$/i
        push(sink, "ole.native.executable", "Ole10Native embeds executable", 4,
          "embedded file #{name} (#{path})")
      else
        push(sink, "ole.native.embedded", "Ole10Native embedded file", 2,
          "embedded file #{name}")
      end
    end
    streams = doc.ole_streams
    if streams.any?(&.downcase.includes?("objectpool"))
      push(sink, "ole.objectpool", "object pool storage", 2, "embedded OLE objects inside document")
    end
    if doc.meta["template"]? && doc.meta["template"] =~ /^(https?|\\\\|file)/i
      push(sink, "doc.remote.template", "remote template in metadata", 3,
        "template = #{doc.meta["template"]}")
    end
    sink
  end

  private def self.rtffile(doc : Doc, scan : Grim::Rtf::Scan) : Array(Finding)
    sink = [] of Finding
    scan.objdata.each do |od|
      case od.kind
      when "OLE compound file"
        push(sink, "rtf.embedded.ole", "embedded OLE object in \\objdata", 2,
          "offset #{od.offset}, #{od.bytes.size} bytes")
      when "PE executable (MZ)"
        push(sink, "rtf.embedded.pe", "PE executable inside \\objdata", 4,
          "offset #{od.offset}")
      when "zip package (PK)"
        push(sink, "rtf.embedded.zip", "zip payload inside \\objdata", 3, "offset #{od.offset}")
      else
        push(sink, "rtf.embedded.blob", "binary blob in \\objdata", 1, "offset #{od.offset}")
      end
    end
    if scan.objclass.any?(&.downcase.includes?("package"))
      push(sink, "rtf.package.object", "Package (packager shell object)", 3,
        "objclass Package — usually a disguised embedded file")
    end
    if scan.objclass.any?(&.downcase.includes?("equation.3"))
      push(sink, "rtf.equation.exploit", "Equation.3 object (CVE-2017-11882 pattern)", 4,
        "Equation Editor exploit class — remote code execution on open")
    end
    unless scan.fields.empty?
      push(sink, "doc.dde.fields", "DDE field codes", 3,
        scan.fields.map(&.word).uniq.join(", "))
      if scan.fields.any? { |f| f.body =~ /(?i)\b(cmd|powershell|mshta|rundll32|wscript|cscript|regsvr32)\b/ }
        push(sink, "doc.dde.executes", "DDE fields spawn interpreters", 4,
          scan.fields.map(&.body).join(" | ")[0, 200])
      end
    end
    if (t = scan.template)
      push(sink, "doc.remote.template", "remote template injection (RTF)", 4,
        "\\*\\template -> #{t}")
    end
    push(sink, "rtf.objupdate", "\\objupdate forces object refresh", 1, "") if scan.objupdate
    if scan.max_depth > 800
      push(sink, "rtf.depth", "extreme group nesting depth", 2,
        "depth #{scan.max_depth} — scanner crash / parser confusion trick")
    end
    if scan.bin_sizes.any? { |s| s > 4_000_000 }
      push(sink, "rtf.bigbin", "huge \\bin object", 2, "binary payload far larger than the visible document")
    end
    unless doc.rtf_ole.empty?
      doc.rtf_ole.each do |d|
        if d.starts_with?("Ole10Native embedded file")
          name = d.split(":")[1]?.to_s.split("(")[0]?.to_s.strip
          if name =~ /\.(exe|scr|pif|bat|cmd|js|vbs|ps1|hta|dll|jar|lnk|iso|img)$/i
            push(sink, "ole.native.executable", "Ole10Native embeds executable", 4, d)
          else
            push(sink, "ole.native.embedded", "Ole10Native embedded file", 2, d)
          end
        elsif d.includes?("vbaProject.bin")
          push(sink, "vba.project", "VBA project present", 2, d)
        end
      end
    end
    sink
  end

  private def self.container(doc : Doc) : Array(Finding)
    sink = [] of Finding
    if doc.onenote
      push(sink, "one.container", "OneNote revision store", 2,
        ".one containers carried the 2023 embed-wave; carving only")
    end
    doc.carves.each do |c|
      case c.kind
      when .starts_with?("PE executable")
        next if c.note.includes?("MZ bytes only")
        push(sink, "carve.pe", "carved PE executable", 3, "offset #{c.offset} (#{c.note})")
      when .starts_with?("OLE compound")
        unless doc.kind == "ole" && c.offset == 0
          push(sink, "carve.ole", "carved OLE compound file", 2, "offset #{c.offset}")
        end
      when .starts_with?("zip")
        unless doc.kind == "ooxml" || c.offset == 0
          push(sink, "carve.zip", "carved zip archive", 1, "offset #{c.offset}")
        end
      when .starts_with?("lnk")
        push(sink, "carve.lnk", "carved LNK shortcut", 3, "offset #{c.offset}")
      when .starts_with?("PDF")
        push(sink, "carve.pdf", "carved PDF document", 1, "offset #{c.offset}")
      else
        push(sink, "carve.#{c.kind.split[0].downcase}", "carved #{c.kind}", 1, "offset #{c.offset}")
      end
    end
    sink
  end

  def self.verdict(doc : Doc) : Verdict
    fs = findings(doc)
    s, force = score(fs)
    Verdict.new(s, band_for(s, force), force, fs)
  end
end
