require "./common"
require "./cfb"
require "./vba"
require "./vbascan"
require "./ooxml"
require "./rtf"
require "./carver"
require "./rules"
require "./forge"

# compiled-in test battery. runs everywhere the binary runs — release
# verification on any machine needs nothing but the binary itself.
module Grim::Selftest
  @@fails = 0
  @@total = 0

  private def self.check(name : String, cond : Bool)
    @@total += 1
    unless cond
      @@fails += 1
      STDERR.puts "  FAIL #{name}"
    end
  end

  private def self.check_eq(name : String, got, want)
    check("#{name} (got=#{got.inspect} want=#{want.inspect})", got == want)
  end

  def self.run : Int32
    puts "grimoire selftest v#{Grim::VERSION}"
    bytes_core
    cfb
    vba
    scanners
    packages
    verdicts
    forge_suite
    hygiene
    puts "  #{@@total - @@fails}/#{@@total} checks passed"
    @@fails == 0 ? 0 : 1
  end

  private def self.bytes_core
    b = Bytes[0x01, 0x02, 0x03, 0x04]
    check_eq("u16le", Grim.u16le(b, 0), 0x0201)
    check_eq("u32le", Grim.u32le(b, 0), 0x04030201)
    check_eq("cp1252 euro", Grim.cp1252(Bytes[0x80]).bytesize, 3) # € = 3 bytes utf8
    tok1 = "ghp_" + "ABCDEFGH" + "IJKLMNOP" + "QR12"
    check_eq("mask ghp", Grim.mask("token #{tok1} here").includes?("REDACTED"), true)
    tok2 = "github_pat_" + "ABCDEFGH" + "IJKLMNOP" + "QRSTUV" + "WX12"
    check_eq("mask github_pat", Grim.mask("x #{tok2} y").includes?("REDACTED"), true)
    tok3 = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    check_eq("mask AKIA", Grim.mask("key #{tok3} end").includes?("REDACTED"), true)
    check_eq("entropy zeros", Grim.entropy(Bytes.new(64, 0_u8)), 0.0)
    check("entropy noise high", Grim.entropy(Bytes.new(4096) { |i| ((i * 31 + 7) % 256).to_u8! }) > 7.0)
    check_eq("printable", Grim.printable_ratio("hello world".to_slice), 1.0)
    iocs = Grim.iocs("see http://203.0.113.9/x and mail agent@cleanmail.invalid or vault.example.com")
    check("iocs kinds", iocs.map(&.kind).uniq.size >= 3)
    d = Grim.defang("http://a.b/c")
    check("defang", d.starts_with?("hxxp") && d.includes?("[.]") && !d.includes?("http"))
  end

  private def self.cfb
    # forged container with small + large streams
    w = Grim::Forge::CfbWriter.new
    w.add("small.txt", "tiny stream body".to_slice)
    w.add("big/blob.bin", Bytes.new(5000) { |i| (i % 251).to_u8! })
    w.add_storage("Vault")
    w.add("Vault/inner.dat", "inner secret".to_slice)
    blob = w.build
    check("cfb magic", Grim::Cfb.match?(blob))
    repo = Grim::Cfb::Repo.new(blob)
    names = repo.streams.map(&.name).sort
    check("cfb streams present", names.includes?("small.txt") && names.includes?("blob.bin") && names.includes?("inner.dat"))
    check_eq("cfb small content", String.new(repo.stream_named("small.txt").not_nil!), "tiny stream body")
    big = repo.stream_named("blob.bin").not_nil!
    check_eq("cfb big size", big.size, 5000)
    check_eq("cfb big content", big[100], (100 % 251).to_u8)
    check_eq("cfb ministream content", String.new(repo.stream_named("inner.dat").not_nil!), "inner secret")
    # garbage rejection
    junk_ok = begin; Grim::Cfb::Repo.new(Bytes.new(512, 1_u8)); false; rescue Grim::Cfb::Error; true; end
    check("cfb rejects junk", junk_ok)
  end

  private def self.vba
    # raw-chunk container round trip
    body = ("Sub AutoOpen()\r\n" * 300).to_slice
    cont = Grim::Forge.raw_container(body)
    dec = Grim::Vba.decompress(cont)
    check("vba raw roundtrip", dec != nil && dec.not_nil!.size == body.size)
    check_eq("vba raw content", dec != nil && dec.not_nil![0, 4] == Bytes[0x53, 0x75, 0x62, 0x20], true)

    # real compressed chunk: build one by hand.
    # header: 0xB000 | (size-3). data: literals then a copy token.
    literals = "ABCDEFGH".to_slice
    # after 8 literals dpos=8 -> diff=4088 >= 271 -> length_bits=8, len mask 255, off mask 0
    # token: length=5 -> tok = (5-3) = 2 ; offset=8 -> offset field = 8-1 = 7 << 8
    tok = ((8 - 1) << 8) | (5 - 3)
    flags = 0b11111111_u8 # 8 bits: 8 literals? no: 8 groups. bit0..7 all 1 = all copy tokens.
    # want: 3 literals + 5 copy-token groups? simpler: encode one literal-flag byte with
    # 8 zero bits = 8 literals, then a token byte.
    io = IO::Memory.new
    io.write_byte(0x01)
    chunk = IO::Memory.new
    chunk.write_byte(0x00_u8) # 8 literals
    "AAAAAAAA".bytes.each { |c| chunk.write_byte(c) }
    # at pin=8: bitcount=4, offset in the high 12 bits, length in the low 4
    tok2 = ((8 - 1) << 12) | (3 - 3)
    chunk.write_byte(0b00000001_u8)
    chunk.write_bytes(tok2.to_u16!, IO::ByteFormat::LittleEndian)
    # the remaining 7 bits of this flag byte are literals
    "BBBBBBB".bytes.each { |c| chunk.write_byte(c) }
    payload = chunk.to_slice
    hdr = 0x8000_u16 | 0x3000_u16 | (payload.size - 1)
    io.write_bytes(hdr, IO::ByteFormat::LittleEndian)
    io.write(payload)
    dec2 = Grim::Vba.decompress(io.to_slice)
    check("vba compressed chunk", dec2 != nil && String.new(dec2.not_nil!) == "AAAAAAAAAAABBBBBBB")

    # project extraction through the forged vbaProject
    code = "Sub AutoOpen()\r\n  Shell \"notepad.exe\"\r\nEnd Sub\r\n"
    blob = Grim::Forge.vba_project([{"Mod1", code}])
    sources = Grim::Vba.extract(blob)
    check_eq("vba extract count", sources.size, 1)
    check("vba extract name", sources[0]?.try(&.name) == "Mod1")
    check("vba extract code", sources[0]?.try(&.code.includes?("Shell \"notepad.exe\"")) == true)
  end

  private def self.scanners
    an = Grim::VbaScan.analyze(<<-VBA)
      Sub AutoOpen()
          Dim sh As Object
          Set sh = CreateObject("WScript.Shell")
          sh.Run "powershell -nop -enc AAAA"
          Dim c As String
          c = Chr(104) & Chr(116) & Chr(116) & Chr(112)
          Open Environ("APPDATA") & "\\x.exe" For Binary As #1
      End Sub
    VBA
    check("vbascan trigger", an.triggers.includes?("AutoOpen"))
    check("vbascan exec", an.hits.any? { |h| h.code == "exec" })
    check("vbascan net?", an.hits.any? { |h| h.text.includes?("powershell") })
    spelled = (["http://203.0.113.42/drop.bin"].join("")).chars.map { |c| "Chr(#{c.ord})" }.join(" & ")
    an2 = Grim::VbaScan.analyze("u = #{spelled}\nShell \"calc\"\n")
    check("vbascan chr decode", an2.decoded.any? { |d| d.kind == "chr-chain" && d.text.includes?("http://203.0.113.42/drop.bin") })
    check("vbascan drop", an.hits.any? { |h| h.code == "drop" })
    an4 = Grim::VbaScan.analyze("sh.RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Sync\", \"y\"\n")
    check("vbascan persist", an4.hits.any? { |h| h.code == "persist" })

    spot = "http://vault-" + "mirror" + ".example.invalid/ld.bin"
    r1 = Grim::VbaScan.analyze("x = StrReverse(\"#{spot.reverse}\")")
    check("strreverse decode", r1.decoded.any? { |d| d.kind == "strreverse" && d.text.includes?(spot) })

    r2 = Grim::VbaScan.analyze("s = \"aHR0cDovLzIwMy4wLjExMy43Ny94LnBocD9pZD0xMjM0NTY3ODkwIg==\"")
    check("b64 decode", r2.decoded.any? { |d| d.kind == "base64" && d.text.includes?("203.0.113.77") })

    hexy = (0...64).map { "41" }.join + "485454503A2F2F"
    r3 = Grim::VbaScan.analyze("h = \"#{hexy}\"")
    check("hex decode text", r3.decoded.any?(&.kind.==("hex-text")))

    # carver
    blob = Bytes.new(2600, 0x20_u8)
    blob[100] = 0x4D_u8; blob[101] = 0x5A_u8
    blob[100 + 0x3C] = 0xC0_u8; blob[100 + 0x3D] = 0_u8; blob[100 + 0x3E] = 0_u8; blob[100 + 0x3F] = 0_u8
    blob[100 + 0xC0] = 0x50_u8; blob[100 + 0xC1] = 0x45_u8; blob[100 + 0xC2] = 0x00_u8; blob[100 + 0xC3] = 0x00_u8
    blob[600] = 0x50_u8; blob[601] = 0x4B_u8; blob[602] = 0x03_u8; blob[603] = 0x04_u8
    ole_at = 600 + 1300
    blob[ole_at] = 0xD0_u8; blob[ole_at + 1] = 0xCF_u8; blob[ole_at + 2] = 0x11_u8; blob[ole_at + 3] = 0xE0_u8
    blob[ole_at + 4] = 0xA1_u8; blob[ole_at + 5] = 0xB1_u8; blob[ole_at + 6] = 0x1A_u8; blob[ole_at + 7] = 0xE1_u8
    carves = Grim::Carver.scan(blob)
    check("carver pe", carves.any? { |c| c.kind.starts_with?("PE") && c.offset == 100 && c.note == "valid PE header" })
    check("carver zip", carves.any? { |c| c.kind.starts_with?("zip") && c.offset == 600 })
    check("carver ole", carves.any? { |c| c.kind.starts_with?("OLE") && c.offset == ole_at })
    check("carver onenote", Grim::Carver.onenote?(Grim::Carver::ONENOTE_GUID + Bytes[1, 2, 3]))
  end

  private def self.packages
    built = Grim::Forge.build("macro")
    doc = Grim::Rules.build(built[:bytes])
    check("macro package detected", doc.kind == "ooxml")
    pkg = doc.package
    check("macro vba part", !!(pkg && pkg.vba_parts.size == 1))
    check("macro source recovered", !!(pkg && pkg.vba_sources.size == 1))

    clean = Grim::Forge.build("clean")
    d2 = Grim::Rules.build(clean[:bytes])
    check("clean format", !!(d2.kind == "ooxml"))
    check("clean no vba", !!((p2 = d2.package) && p2.vba_parts.empty?))

    t = Grim::Forge.build("template")
    d3 = Grim::Rules.build(t[:bytes])
    check("template ext rels", !!((p3 = d3.package) && p3.ext_rels.size == 1))
    check("template attached", !!((p3b = d3.package) && p3b.ext_rels[0].attached_template))

    x = Grim::Forge.build("xlm")
    d4 = Grim::Rules.build(x[:bytes])
    check("xlm sheets", !!((p4 = d4.package) && p4.macrosheets.size == 1))
    check("xlm calls", !!((p4b = d4.package) && p4b.xlm_calls.includes?("EXEC")))

    rtf = Grim::Forge.build("dde")
    d5 = Grim::Rules.build(rtf[:bytes])
    check("rtf format", !!(d5.kind == "rtf"))
    scan = d5.rtf
    check("rtf dde fields", !!(scan && scan.fields.any? { |f| f.word == "DDEAUTO" }))
    check("rtf objdata ole", !!(scan && scan.objdata.any? { |o| o.kind == "OLE compound file" }))
    check("rtf objupdate", !!(scan && scan.objupdate))
    check("rtf package class", !!(scan && scan.objclass.any?(&.downcase.==("package"))))
    check("rtf ole details", !!(d5.rtf_ole.any?(&.includes?("Ole10Native embedded file: shipment_label"))))

    n = Grim::Forge.build("native")
    d6 = Grim::Rules.build(n[:bytes])
    check("native format", !!(d6.kind == "ole"))
    check("native ole10native", !!((o6 = d6.ole10native) && o6[0] == "shipment_label.scr"))
    check("native meta", !!(d6.meta["author"]? == "logistics.desk"))
    check("native template meta", (d6.meta["template"]? || "").includes?("203.0.113.77"))

    c = Grim::Forge.build("carve")
    d7 = Grim::Rules.build(c[:bytes])
    check("carve onenote detect", !!(d7.onenote))
    check("carve pe found", !!(d7.carves.any? { |f| f.kind.starts_with?("PE") && f.note == "valid PE header" }))
    check("carve ole found", !!(d7.carves.any? { |f| f.kind.starts_with?("OLE") }))
    check("carve zip found", !!(d7.carves.any? { |f| f.kind.starts_with?("zip") }))
  end

  private def self.verdicts
    clean_v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("clean")[:bytes]))
    check_eq("clean verdict", clean_v.band, "clean")
    check_eq("clean exit", Grim::Rules::BAND_EXIT[clean_v.band], 0)

    macro_v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("macro")[:bytes]))
    check("macro hostile", macro_v.band == "hostile" || macro_v.band == "suspicious")
    check("macro chain force", macro_v.findings.any? { |f| f.id == "vba.autoexec.downloader" })
    check("macro regwrite", macro_v.findings.any? { |f| f.id == "vba.persist" })

    tpl_v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("template")[:bytes]))
    check("template finding", tpl_v.findings.any? { |f| f.id == "doc.remote.template" })

    dde_v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("dde")[:bytes]))
    check("dde force", dde_v.findings.any? { |f| f.id == "doc.dde.executes" })
    check("dde hostile", dde_v.band == "hostile")

    nat_v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("native")[:bytes]))
    check("native exe force", nat_v.findings.any? { |f| f.id == "ole.native.executable" })
    check("native template meta", nat_v.findings.any? { |f| f.id == "doc.remote.template" })

    # score math
    fs = [Grim::Rules::Finding.new("a", "a", 2, ""), Grim::Rules::Finding.new("b", "b", 3, "")]
    s, f = Grim::Rules.score(fs)
    check_eq("score sum", s, 2 * 6 + 3 * 6)
    s2, _ = Grim::Rules.score([Grim::Rules::Finding.new("vba.autoexec.downloader", "x", 4, "")])
    check("force flag", Grim::Rules.band_for(s2, true) == "hostile")
    check("dedupe", Grim::Rules.score([Grim::Rules::Finding.new("a", "a", 4, ""), Grim::Rules::Finding.new("a", "a", 4, "")])[0] == 4 * 6)
  end

  private def self.forge_suite
    Grim::Forge::SCENARIOS.each do |sc|
      a = Grim::Forge.build(sc)[:bytes]
      b = Grim::Forge.build(sc)[:bytes]
      check_eq("forge deterministic #{sc}",
        OpenSSL::Digest.new("SHA256").update(a).final.hexstring,
        OpenSSL::Digest.new("SHA256").update(b).final.hexstring)
    end
  end

  private def self.hygiene
    # reports never leak fixture credential shapes
    tok = Base64.decode_string("Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUjEy")
    code = "x = \"#{tok}\"\nShell \"cmd\"\n"
    blob = Grim::Forge.vba_project([{"Mod1", code}])
    built_bytes = Grim::Forge.zip([
      {"[Content_Types].xml", "<Types/>".to_slice},
      {"word/document.xml", "<w:doc/>".to_slice},
      {"word/vbaProject.bin", blob},
    ])
    doc = Grim::Rules.build(built_bytes)
    v = Grim::Rules.verdict(doc)
    out = Grim::Report.json(doc, v, "x.docm") + Grim::Report.terminal(doc, v, "x.docm", false, true)
    check("hygiene no token", !out.includes?(tok))
    check("json single line", !Grim::Report.json(doc, v, "x.docm").includes?("\n"))
    parsed = JSON.parse(Grim::Report.json(doc, v, "x.docm"))
    check("json parses", parsed["band"].as_s == v.band)
    check("json findings", parsed["findings"].as_a.size == v.findings.size)
  end
end
