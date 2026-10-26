require "spec"
require "../rites/common"
require "../rites/cfb"
require "../rites/vba"
require "../rites/vbascan"
require "../rites/ooxml"
require "../rites/rtf"
require "../rites/carver"
require "../rites/rules"
require "../rites/forge"
require "../rites/report"

describe Grim::Cfb do
  it "round-trips a forged container" do
    w = Grim::Forge::CfbWriter.new
    w.add("a.txt", "hello".to_slice)
    w.add("deep/nest/blob.bin", Bytes.new(4200) { |i| (i % 251).to_u8! })
    blob = w.build
    repo = Grim::Cfb::Repo.new(blob)
    String.new(repo.stream_named("a.txt").not_nil!).should eq "hello"
    big = repo.stream_named("blob.bin").not_nil!
    big.size.should eq 4200
    big[7].should eq (7 % 251).to_u8
  end

  it "reads summary information metadata" do
    doc = Grim::Rules.build(Grim::Forge.build("native")[:bytes])
    doc.meta["author"].should eq "logistics.desk"
    doc.meta["title"].should eq "shipment report"
  end

  it "rejects garbage" do
    expect_raises(Grim::Cfb::Error) do
      Grim::Cfb::Repo.new(Bytes.new(512, 7_u8))
    end
  end
end

describe Grim::Vba do
  it "decompresses raw chunks" do
    body = ("Spell = 1\r\n" * 400).to_slice
    dec = Grim::Vba.decompress(Grim::Forge.raw_container(body))
    dec.should_not be_nil
    dec.not_nil!.should eq body
  end

  it "decompresses copy tokens" do
    io = IO::Memory.new
    io.write_byte(0x01_u8)
    ch = IO::Memory.new
    ch.write_byte(0x00_u8)
    "AAAAAAAA".each_char { |c| ch.write_byte(c.ord.to_u8!) }
    tok = ((8 - 1) << 12) | (3 - 3)
    ch.write_byte(0b00000001_u8)
    ch.write_bytes(tok.to_u16!, IO::ByteFormat::LittleEndian)
    "BBBBBBB".each_char { |c| ch.write_byte(c.ord.to_u8!) }
    payload = ch.to_slice
    io.write_bytes(0x8000_u16 | 0x3000_u16 | (payload.size - 1), IO::ByteFormat::LittleEndian)
    io.write(payload)
    String.new(Grim::Vba.decompress(io.to_slice).not_nil!).should eq "AAAAAAAAAAABBBBBBB"
  end

  it "extracts module source from a forged project" do
    code = "Sub AutoOpen()\r\n  Shell \"calc\"\r\nEnd Sub\r\n"
    sources = Grim::Vba.extract(Grim::Forge.vba_project([{"Rune1", code}]))
    sources.size.should eq 1
    sources[0].name.should eq "Rune1"
    sources[0].code.should contain "AutoOpen"
  end
end

describe Grim::VbaScan do
  it "flags triggers, chains and decoded payloads" do
    spelled = "http://203.0.113.42/quiet.bin".chars.map { |c| "Chr(#{c.ord})" }.join(" & ")
    an = Grim::VbaScan.analyze(<<-VBA
      Sub Workbook_Open()
          Set sh = CreateObject("WScript.Shell")
          sh.Run "calc"
          u = #{spelled}
          Open Environ("APPDATA") & "\\q.exe" For Binary As #1
      End Sub
    VBA
    )
    an.triggers.should contain("Workbook_Open")
    an.hits.any? { |h| h.code == "exec" }.should be_true
    an.hits.any? { |h| h.code == "drop" }.should be_true
    an.decoded.any? { |d| d.kind == "chr-chain" && d.text.includes?("http://203.0.113.42/quiet.bin") }.should be_true
  end

  it "decodes strreverse and base64" do
    spot = "http://vault-mirror.example.invalid/ld.bin"
    spot = "http://vault-mirror.example.invalid/ld.bin"
    r1 = Grim::VbaScan.analyze("x = StrReverse(\"#{spot.reverse}\")")
    r1.decoded.any? { |d| d.kind == "strreverse" && d.text.includes?(spot) }.should be_true
    r2 = Grim::VbaScan.analyze(%q(s = "aHR0cDovLzIwMy4wLjExMy43Ny94LnBocD9pZD0xMjM0NTY3ODkwIg=="))
    r2.decoded.any? { |d| d.kind == "base64" && d.text.includes?("203.0.113.77") }.should be_true
  end
end

describe Grim::Ooxml do
  it "sees the remote template trick" do
    doc = Grim::Rules.build(Grim::Forge.build("template")[:bytes])
    pkg = doc.package.not_nil!
    pkg.ext_rels.size.should eq 1
    pkg.ext_rels[0].attached_template.should be_true
  end

  it "reads XLM macro sheets" do
    doc = Grim::Rules.build(Grim::Forge.build("xlm")[:bytes])
    pkg = doc.package.not_nil!
    pkg.macrosheets.size.should eq 1
    pkg.xlm_calls.should contain("EXEC")
  end
end

describe Grim::Rtf do
  it "finds DDE fields, package objects and OLE objdata" do
    doc = Grim::Rules.build(Grim::Forge.build("dde")[:bytes])
    scan = doc.rtf.not_nil!
    scan.fields.any? { |f| f.word == "DDEAUTO" }.should be_true
    scan.objclass.should contain("Package")
    scan.objdata[0].kind.should eq "OLE compound file"
    doc.rtf_ole.any?(&.includes?("Ole10Native embedded file: shipment_label")).should be_true
  end
end

describe Grim::Carver do
  it "carves embedded artifacts by magic" do
    blob = Bytes.new(2600, 0x20_u8)
    blob[100] = 0x4D_u8
    blob[101] = 0x5A_u8
    blob[100 + 0x3C] = 0xC0_u8
    blob[100 + 0x3D] = 0_u8
    blob[100 + 0x3E] = 0_u8
    blob[100 + 0x3F] = 0_u8
    blob[100 + 0xC0] = 0x50_u8
    blob[100 + 0xC1] = 0x45_u8
    blob[100 + 0xC2] = 0_u8
    blob[100 + 0xC3] = 0_u8
    finds = Grim::Carver.scan(blob)
    finds.any? { |c| c.kind.starts_with?("PE") && c.note == "valid PE header" }.should be_true
  end

  it "recognizes onenote stores" do
    Grim::Carver.onenote?(Grim::Carver::ONENOTE_GUID + Bytes[1]).should be_true
  end
end

describe Grim::Rules do
  it "bands the clean fixture as clean with exit 0" do
    v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("clean")[:bytes]))
    v.band.should eq "clean"
    Grim::Rules::BAND_EXIT[v.band].should eq 0
  end

  it "forces hostile on the autoexec + fetch + drop chain" do
    v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("macro")[:bytes]))
    v.findings.any? { |f| f.id == "vba.autoexec.downloader" }.should be_true
    v.band.should eq "hostile"
  end

  it "forces hostile on DDE interpreter spawn" do
    v = Grim::Rules.verdict(Grim::Rules.build(Grim::Forge.build("dde")[:bytes]))
    v.findings.any? { |f| f.id == "doc.dde.executes" }.should be_true
    v.band.should eq "hostile"
  end

  it "dedupes findings by id" do
    fs = [Grim::Rules::Finding.new("x", "x", 4, ""), Grim::Rules::Finding.new("x", "x", 4, "")]
    Grim::Rules.score(fs)[0].should eq 24
  end
end

describe Grim::Forge do
  it "builds every scenario byte-deterministically" do
    Grim::Forge::SCENARIOS.each do |sc|
      a = Grim::Forge.build(sc)[:bytes]
      b = Grim::Forge.build(sc)[:bytes]
      OpenSSL::Digest.new("SHA256").update(a).final.hexstring
        .should eq OpenSSL::Digest.new("SHA256").update(b).final.hexstring
    end
  end
end

describe Grim::Report do
  it "keeps credentials out of every renderer" do
    tok = Base64.decode_string("Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUjEy")
    code = "x = \"#{tok}\"\nShell \"cmd\"\n"
    pkg = Grim::Forge.vba_project([{"Mod1", code}])
    bytes = Grim::Forge.zip([
      {"[Content_Types].xml", "<Types/>".to_slice},
      {"word/document.xml", "<w:doc/>".to_slice},
      {"word/vbaProject.bin", pkg},
    ])
    doc = Grim::Rules.build(bytes)
    v = Grim::Rules.verdict(doc)
    out = Grim::Report.json(doc, v, "x.docm") +
          Grim::Report.terminal(doc, v, "x.docm", false, true) +
          Grim::Report.markdown(doc, v, "x.docm")
    out.includes?(tok).should be_false
    Grim::Report.json(doc, v, "x.docm").includes?("\n").should be_false
  end
end
