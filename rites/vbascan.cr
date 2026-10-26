require "./common"
require "base64"

# VBA source analysis: auto-exec triggers, hostile API census, and the
# deobfuscation layer (Chr()/ChrW/ChrB chains, StrReverse, base64, hex blobs).
# every decoded payload gets re-scanned — encoded trickery is still trickery.
module Grim::VbaScan
  # event handlers that fire without user interaction
  TRIGGERS = [
    "Auto_Open", "AutoOpen", "Auto_Close", "AutoClose", "Auto_New", "AutoNew",
    "Workbook_Open", "Workbook_Activate", "Workbook_BeforeClose", "Workbook_Deactivate",
    "Document_Open", "Document_AutoOpen", "Document_Close", "Document_BeforeClose",
    "Document_BeforePrint", "Document_New", "Presentation_Open", "Presentation_Close",
    "InkPicture_Painted", "InkPicture1_Painted", "Image1_Click", "Label1_Click",
    "txt1_Changed", "TextBox1_Change", "_OnConnecting", "UserForm_Initialize",
    "Application_WorkbookOpen", "App_WorkbookOpen", "ComboBox1_Change",
  ]

  # API / behavior markers observed in live campaigns
  KEYS = [
    {"exec", "Shell(", 2},
    {"exec", "WScript.Shell", 3},
    {"exec", ".Run ", 2},
    {"exec", ".Exec(", 2},
    {"exec", "ShellExecute", 2},
    {"exec", "CreateObject(", 1},
    {"exec", "GetObject(", 1},
    {"exec", "ExecuteGlobal", 3},
    {"exec", "CallByName", 2},
    {"exec", "Eval(", 2},
    {"net", "MSXML2.XMLHTTP", 3},
    {"net", "MSXML2.ServerXMLHTTP", 3},
    {"net", "WinHttp.WinHttpRequest", 3},
    {"net", "WinInet", 2},
    {"net", "InternetOpen", 2},
    {"net", "URLDownloadToFile", 4},
    {"net", "Net.WebClient", 4},
    {"net", "DownloadFile", 3},
    {"net", "winmgmts:", 3},
    {"net", "winmgmts", 3},
    {"drop", "ADODB.Stream", 4},
    {"drop", "SaveToFile", 4},
    {"drop", "For Binary", 3},
    {"drop", "For Output", 2},
    {"drop", "Put #", 3},
    {"persist", "RegWrite", 4},
    {"persist", "RegRead", 2},
    {"persist", "CurrentVersion\\Run", 4},
    {"persist", "SchTasks", 3},
    {"persist", "schtasks", 3},
    {"evade", "Environ(", 2},
    {"evade", "USERPROFILE", 1},
    {"evade", "APPDATA", 1},
    {"evade", "TaskVisible", 3},
    {"evade", "VirtualMachineDetect", 3},
    {"evade", "IsVM", 2},
    {"evade", "Application.ScreenUpdating", 1},
    {"evade", "On Error Resume Next", 1},
    {"evade", "Option Explicit", 0},
    {"proc", "kernel32", 3},
    {"proc", "WriteProcessMemory", 4},
    {"proc", "VirtualAlloc", 4},
    {"proc", "CreateThread", 4},
    {"proc", "GetProcAddress", 3},
    {"proc", "LoadLibrary", 3},
    {"proc", "RtlMoveMemory", 4},
    {"proc", "CreateObject(\"Scripting.FileSystemObject\")", 2},
    {"proc", "cmd.exe", 3},
    {"proc", "powershell", 3},
    {"proc", "certutil", 4},
    {"proc", "bitsadmin", 4},
    {"proc", "rundll32", 3},
    {"proc", "regsvr32", 3},
    {"proc", "mshta", 4},
    {"proc", "wscript", 2},
    {"proc", "cscript", 2},
  ]

  record Hit, code : String, text : String, count : Int32, sev : Int32

  record Decoded, kind : String, text : String, findings : Array(Hit), iocs : Array(Grim::Ioc)

  record Analysis,
    triggers : Array(String),
    hits : Array(Hit),
    decoded : Array(Decoded),
    iocs : Array(Grim::Ioc),
    entropy : Float64,
    lines : Int32,
    chr_calls : Int32,
    concat_joins : Int32,
    long_b64 : Int32

  def self.analyze(code : String) : Analysis
    code = code.scrub
    low = code.downcase
    triggers = TRIGGERS.select do |t|
      idx = low.index(t.downcase)
      next false unless idx
      # word-boundary: char before must not be alnum/underscore
      prev_ok = idx == 0 || !alnum?(low[idx - 1])
      prev_ok
    end

    hits = [] of Hit
    KEYS.each do |key, text, sev|
      next if sev == 0
      c = count_ci(code, text)
      next if c == 0
      hits << Hit.new(key, text, c, sev)
    end

    chr_calls = code.scan(/(?i)\bchr[bw]?\s*\(/).size
    concat_joins = code.scan(/&\s*_\s*\n/).size
    b64runs = code.scan(/(?:[A-Za-z0-9+\/]{40,}={0,2})/)
    long_b64 = b64runs.size

    decoded = [] of Decoded
    decoded.concat(decode_chr(code))
    decoded.concat(decode_reverse(code))
    decoded.concat(decode_b64(code))
    decoded.concat(decode_hex(code))

    iocs = Grim.iocs(code)
    decoded.each { |d| iocs = iocs.concat(d.iocs) }
    iocs = dedupe_iocs(iocs)

    Analysis.new(triggers, hits, decoded, iocs,
      Grim.entropy(code.to_slice), code.lines.size, chr_calls, concat_joins, long_b64)
  end

  private def self.alnum?(c : Char) : Bool
    c.alphanumeric? || c == '_'
  end

  private def self.count_ci(hay : String, needle : String) : Int32
    clean = hay.scrub.downcase
    clean.scan(Regex.new(Regex.escape(needle.downcase))).size
  end

  # Chr(65) / ChrW(&H41) / ChrB(...) chains -> characters
  CHR_OUTER = /\bchr[bw]?\s*\(\s*(?:&h[0-9a-f]+|\d{1,7})\s*\)/i
  CHR_INNER = /\(\s*(?:&h([0-9a-f]+)|(\d{1,7}))\s*\)/i

  CHR_CHAIN = /(?:\bchr[bw]?\s*\([^)]*\))(?:\s*&\s*\bchr[bw]?\s*\([^)]*\))*/i

  def self.decode_chr(code : String) : Array(Decoded)
    text = code.gsub(CHR_CHAIN) do |chain|
      chain.gsub(CHR_OUTER) do |one|
        if (inner = one.match(CHR_INNER))
          if (g1 = inner[1]?)
            (g1.to_i(16) & 0xFF).chr.to_s
          else
            v = (inner[2]? || "0").to_i & 0xFFFF
            v <= 0x10FFFF && v >= 32 ? v.chr.to_s : ""
          end
        else
          one
        end
      end.gsub(/\s*&\s*/, "")
    end
    return [] of Decoded if text == code
    # only interesting when the reconstruction is long enough to mean something
    interesting = text.scan(/[\x20-\x7e]{24,}/).map(&.[0])
    out = [] of Decoded
    interesting.each do |s|
      next if s =~ /(?i)\b(sub|end|dim|set|if|then|else|for|next|function)\b/
      findings = rescan(s)
      out << Decoded.new("chr-chain", s, findings, Grim.iocs(s))
    end
    out.uniq { |d| d.text }[0, 12]
  end

  # StrReverse("literal") -> the literal reversed
  def self.decode_reverse(code : String) : Array(Decoded)
    out = [] of Decoded
    code.scan(/(?i)strreverse\s*\(\s*"([^"]{12,})"\s*\)/) do |m|
      rev = m[1].reverse
      next if rev.empty?
      out << Decoded.new("strreverse", rev, rescan(rev), Grim.iocs(rev))
    end
    out.uniq { |d| d.text }[0, 12]
  end

  # long base64 runs embedded in source
  def self.decode_b64(code : String) : Array(Decoded)
    out = [] of Decoded
    code.scan(/(?:[A-Za-z0-9+\/]{40,}={0,2})/) do |m|
      raw = m[0]
      next unless raw.size % 4 == 0 || raw.size % 4 == 2 || raw.size % 4 == 3
      begin
        blob = Base64.decode_string(raw)
      rescue
        next
      end
      next unless Grim.printable_ratio(blob.to_slice) > 0.85
      safe = blob.scrub
      out << Decoded.new("base64", safe[0, 2048], rescan(safe), Grim.iocs(safe))
    end
    out.uniq { |d| d.text }[0, 8]
  end

  # long hex literals that decode to text or binary headers
  def self.decode_hex(code : String) : Array(Decoded)
    out = [] of Decoded
    code.scan(/(?:[0-9A-Fa-f]{2}){32,}/) do |m|
      h = m[0]
      begin
        blob = h.hexbytes?
      rescue
        next
      end
      next unless blob
      if Grim.printable_ratio(blob) > 0.85
        txt = String.new(blob).scrub
        out << Decoded.new("hex-text", txt[0, 2048], rescan(txt), Grim.iocs(txt))
      elsif blob.size > 8 && (blob[0, 2] == Bytes[0x4D, 0x5A] || blob[0, 2] == Bytes[0x50, 0x4B] || blob[0, 4] == Bytes[0xD0, 0xCF, 0x11, 0xE0])
        kind = blob[0, 2] == Bytes[0x4D, 0x5A] ? "embedded PE (MZ)" : blob[0, 2] == Bytes[0x50, 0x4B] ? "embedded zip (PK)" : "embedded OLE (D0CF)"
        out << Decoded.new("hex-blob", "#{kind}, #{blob.size} bytes", [] of Hit, [] of Grim::Ioc)
      end
    end
    out.uniq { |d| d.text }[0, 8]
  end

  # re-scan any decoded payload for the same markers as source
  def self.rescan(text : String) : Array(Hit)
    hits = [] of Hit
    KEYS.each do |key, kw, sev|
      next if sev == 0
      c = count_ci(text, kw)
      next if c == 0
      hits << Hit.new("decoded:#{key}", kw, c, sev)
    end
    hits
  end

  private def self.dedupe_iocs(list : Array(Grim::Ioc)) : Array(Grim::Ioc)
    seen = Set(String).new
    list.select do |i|
      k = "#{i.kind}:#{i.value}"
      seen.add?(k)
    end
  end
end
