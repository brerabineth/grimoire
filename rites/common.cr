module Grim
  VERSION = "0.1.0"

  # byte-level helpers shared by every reader

  def self.u16le(b : Bytes, o : Int) : UInt16
    (b[o].to_u16! | (b[o + 1].to_u16! << 8))
  end

  def self.u32le(b : Bytes, o : Int) : UInt32
    (b[o].to_u32! | (b[o + 1].to_u32! << 8) | (b[o + 2].to_u32! << 16) | (b[o + 3].to_u32! << 24))
  end

  def self.u64le(b : Bytes, o : Int) : UInt64
    v = 0_u64
    8.times { |i| v |= b[o + i].to_u64! << (8 * i) }
    v
  end

  # CP1252 (most common VBA codepage). maps high bytes to unicode points,
  # undefined slots fall back to the latin-1 identity.
  CP1252 = [8364, 129, 8218, 402, 8222, 8230, 8224, 8225, 710, 8240, 352, 8249, 381, 8217, 8216, 8220, 8221, 8226, 8211, 8212, 732, 8482, 353, 8250, 382, 376, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]

  def self.cp1252(b : Bytes) : String
    String.build(b.size) do |s|
      b.each do |x|
        if x < 0x80 || x >= 0xA0
          s << x.chr
        else
          cp = CP1252[x - 0x80]
          s << (cp < 0x100 ? cp.chr : cp.unsafe_chr)
        end
      end
    end
  end

  def self.entropy(b : Bytes) : Float64
    return 0.0 if b.empty?
    hist = Array(Int32).new(256, 0)
    b.each { |x| hist[x] += 1 }
    e = 0.0
    hist.each do |c|
      next if c == 0
      p = c.to_f64 / b.size
      e -= p * Math.log2(p)
    end
    e
  end

  # printability ratio: how much of a blob decodes to sane text
  def self.printable_ratio(b : Bytes) : Float64
    return 0.0 if b.empty?
    ok = b.count { |x| x == 0x0a || x == 0x0d || x == 0x09 || (x >= 0x20 && x < 0x7f) || x >= 0xA0 }
    ok.to_f64 / b.size
  end

  # single-pass union masking of credential-shaped literals, so reports never
  # leak a secret even when a document contains one.
  TOKEN_PATTERNS = [
    /github_pat_[A-Za-z0-9_]{20,}/,
    /gh[pousr]_[A-Za-z0-9]{20,}/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bASIA[0-9A-Z]{16}\b/,
    /sk-[A-Za-z0-9_-]{20,}/,
    /xox[baprs]-[A-Za-z0-9-]{10,}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  ]

  def self.mask(text : String) : String
    out = text
    TOKEN_PATTERNS.each_with_index do |re, i|
      out = out.gsub(re) { "[REDACTED:#{i}]" }
    end
    out
  end

  def self.clip(text : String, n : Int = 110) : String
    t = text.gsub(/[\x00-\x08\x0b\x0c\x0e-\x1f]/, " ")
    return t if t.size <= n
    t[0, n - 1] + "…"
  end

  def self.defang(s : String) : String
    s.gsub(/(?i)\bhttp/, "hxxp").gsub(/\./, "[.]").gsub(": //", "[:]").gsub("://", "[:]")
  end

  URL_RE      = /(?:h(?:tt|x)ps?|h(?:tt|x)p|ftp):\/\/[A-Za-z0-9._~:\/?#\[\]@!$&'()*+,;=%-]{4,}/i
  IPV4_RE     = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/
  EMAIL_RE    = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/
  # bare domain: word.word.tld not preceded by scheme, kept conservative
  BAREHOST_RE = /\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+(?:com|net|org|info|xyz|top|icu|ru|su|cn|tk|ml|ga|cf|gq|pw|cc|biz|online|site|shop|link|live|space|fun|store|vip)\b/i

  record Ioc, kind : String, value : String

  def self.iocs(text : String) : Array(Ioc)
    out = [] of Ioc
    seen = Set(String).new
    text.scan(URL_RE) do |m|
      v = m[0].chomp(".,;)")
      k = v =~ /h(?:tt|x)p/i ? "url" : "url(ftp)"
      next unless seen.add?(v)
      out << Ioc.new(k, v)
    end
    text.scan(IPV4_RE) do |m|
      v = m[0]
      next unless seen.add?(v)
      out << Ioc.new("ip", v)
    end
    text.scan(EMAIL_RE) do |m|
      v = m[0]
      next unless seen.add?(v)
      out << Ioc.new("email", v)
    end
    text.scan(BAREHOST_RE) do |m|
      v = m[0].downcase
      next unless seen.add?(v)
      out << Ioc.new("domain", v)
    end
    out
  end

  def self.hexdump?(b : Bytes, n : Int = 32) : String
    b[0, Math.min(n, b.size)].hexstring
  end
end
