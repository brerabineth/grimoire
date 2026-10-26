require "./common"
require "json"
require "./rules"
require "./forge"

# renderers: ANSI terminal cards, canonical single-line JSON, markdown.
# outputs are path-safe (only what the caller passed) and secret-masked.
module Grim::Report
  C = {
    "reset"  => "\e[0m",
    "dim"    => "\e[2m",
    "red"    => "\e[31m",
    "green"  => "\e[32m",
    "yellow" => "\e[33m",
    "magenta"=> "\e[35m",
    "cyan"   => "\e[36m",
    "white"  => "\e[97m",
    "bold"   => "\e[1m",
  }

  BAND_COLOR = {"clean" => "green", "watch" => "cyan", "suspicious" => "yellow", "hostile" => "red"}
  SEV_LABEL  = {1 => "low", 2 => "medium", 3 => "high", 4 => "critical"}

  def self.paint(s : String, color : String, use_color : Bool) : String
    use_color ? C[color] + s + C["reset"] : s
  end

  BANNER = <<-BANNER
      ▄████  ██▀███  ██▓▓█████▄  ▄▄▄       ███▄ ▄███▓
     ██▒ ▀█▒▓██ ▒ ██▒▓██▒▒██▀ ██▌▒████▄    ▓██▒▀█▀ ██▒
    ▒██░▄▄▄░▓██ ░▄█ ▒▒██▒░██   █▌▒██  ▀█▄  ▓██    ▓██░
    ░▓█  ██▓▒██▀▀█▄  ░██░░▓█▄   ▌░██▄▄▄▄██ ▒██    ▒██
    ░▒▓███▀▒░██▓ ▒██▒░██░░▒████▓  ▓█   ▓██▒▒██▒   ░██▒
  BANNER

  def self.terminal(doc : Grim::Rules::Doc, verdict : Grim::Rules::Verdict, path : String, use_color : Bool, show_all : Bool) : String
    io = IO::Memory.new
    band = verdict.band
    col = BAND_COLOR[band]
    io << "\n"
    io << paint("  grimoire v#{Grim::VERSION} — document triage", "dim", use_color) << "\n"
    io << paint("  file     ", "white", use_color) << File.basename(path) << "\n"
    io << paint("  verdict  ", "white", use_color) << paint(band.upcase, col, use_color)
    io << paint("  score #{verdict.score}/100", "dim", use_color) << "\n"
    io << paint("  format   ", "white", use_color) << doc.kind << (doc.onenote ? " (onenote)" : "") << "\n"
    io << paint("  size     ", "white", use_color) << "#{doc.size} bytes\n"
    io << paint("  sha256   ", "white", use_color) << doc.sha256 << "\n"
    unless doc.error.nil?
      io << paint("  note     ", "yellow", use_color) << doc.error.not_nil! << "\n"
    end
    unless doc.meta.empty?
      doc.meta.keys.sort.each do |k|
        io << paint("  meta     ", "white", use_color) << "#{k}: #{Grim.clip(doc.meta[k], 70)}\n"
      end
    end
    io << "\n"

    if verdict.findings.empty?
      io << paint("  no spells found. the document reads clean.", "green", use_color) << "\n"
    else
      groups = {4 => [] of Grim::Rules::Finding, 3 => [] of Grim::Rules::Finding, 2 => [] of Grim::Rules::Finding, 1 => [] of Grim::Rules::Finding}
      verdict.findings.each { |f| groups[f.sev] << f }
      {4, 3, 2, 1}.each do |sev|
        next if groups[sev].empty?
        if !show_all && sev < 2 && band == "hostile"
          next
        end
        label = SEV_LABEL[sev]
        c = sev >= 4 ? "red" : sev == 3 ? "yellow" : "cyan"
        io << paint("  ▸ #{groups[sev].size} #{label}", c, use_color) << "\n"
        groups[sev].each do |f|
          io << paint("    · #{f.title}", "white", use_color) << "\n"
          io << paint("      #{f.id}", "dim", use_color)
          io << (f.detail.empty? ? "\n" : " — #{f.detail}\n")
        end
      end
      # IOCs
      iocs = collect_iocs(doc)
      unless iocs.empty?
        io << "\n" << paint("  indicators (defanged)", "magenta", use_color) << "\n"
        iocs[0, 14].each do |i|
          io << "    #{i.kind.rjust(6)}  " << Grim.defang(i.value) << "\n"
        end
        io << paint("    … #{iocs.size} total", "dim", use_color) << "\n" if iocs.size > 14
      end
    end
    io << "\n"
    io.to_s
  end

  def self.collect_iocs(doc : Grim::Rules::Doc) : Array(Grim::Ioc)
    out = [] of Grim::Ioc
    if (pkg = doc.package)
      pkg.ext_rels.each { |r| out.concat(Grim.iocs(r.target)) }
      pkg.vba_sources.each do |s|
        an = Grim::VbaScan.analyze(s.code)
        out.concat(an.iocs)
      end
    end
    if (rtf = doc.rtf)
      out.concat(rtf.iocs)
    end
    if (repo = doc.ole)
      repo.streams.each do |st|
        next if st.size > 2_000_000
        blob = repo.stream(st)
        txt = Grim.cp1252(blob[0, Math.min(blob.size, 65536)])
        out.concat(Grim.iocs(txt))
      end
    end
    seen = Set(String).new
    out.select { |i| seen.add?("#{i.kind}:#{i.value}") }
  end

  # macro source dump for the `spells` command
  def self.spells(doc : Grim::Rules::Doc, path : String, use_color : Bool) : String
    io = IO::Memory.new
    io << "\n" << paint("  grimoire — spellbook of #{File.basename(path)}", "dim", use_color) << "\n"
    sources = [] of Tuple(String, String)
    if (pkg = doc.package)
      pkg.vba_sources.each { |s| sources << {s.name, s.code} }
    end
    if (repo = doc.ole)
      repo.streams.each do |st|
        next unless st.name.downcase == "vbaproject.bin"
        Grim::Vba.extract(repo.stream(st)).each { |s| sources << {s.name, s.code} }
      end
    end
    if sources.empty?
      io << "  no macro source recovered.\n\n"
      return io.to_s
    end
    sources.each do |name, code|
      io << "\n" << paint("  ── module #{name} " + ("─" * 24), "cyan", use_color) << "\n"
      code.each_line.with_index(1) do |line, ln|
        marked = line.strip.downcase.starts_with?("attribute vb_") ? paint(line, "dim", use_color) : line
        io << sprintf("  %4d │ %s\n", ln, marked)
      end
    end
    io << "\n"
    io.to_s
  end

  def self.carves(doc : Grim::Rules::Doc, path : String, use_color : Bool) : String
    io = IO::Memory.new
    io << "\n" << paint("  grimoire — carved artifacts of #{File.basename(path)}", "dim", use_color) << "\n"
    if doc.carves.empty?
      io << "  nothing recognizable embedded.\n\n"
      return io.to_s
    end
    doc.carves.each do |c|
      io << sprintf("  %8d  %-22s %s\n", c.offset, c.kind, c.note)
    end
    io << "\n"
    io.to_s
  end

  def self.ioc_list(doc : Grim::Rules::Doc, path : String, use_color : Bool) : String
    io = IO::Memory.new
    collect_iocs(doc).each do |i|
      io << "#{i.kind}\t#{Grim.defang(i.value)}\n"
    end
    io.to_s
  end

  # ---- json (single line, keys sorted where handed-built) -----------------

  def self.json(doc : Grim::Rules::Doc, verdict : Grim::Rules::Verdict, path : String) : String
    JSON.build do |j|
      j.object do
        j.field("artifact", File.basename(path))
        j.field("format", doc.kind)
        j.field("size", doc.size)
        j.field("sha256", doc.sha256)
        j.field("score", verdict.score)
        j.field("band", verdict.band)
        unless doc.error.nil?
          j.field("error", doc.error.not_nil!)
        end
        unless doc.meta.empty?
          j.field("metadata") do
            j.object do
              doc.meta.keys.sort.each { |k| j.field(k, doc.meta[k]) }
            end
          end
        end
        if (pkg = doc.package)
          j.field("parts", pkg.parts.size)
          j.field("vba_parts", pkg.vba_parts.size)
          j.field("active_x", pkg.active_x)
          j.field("external_relations") do
            j.array do
              pkg.ext_rels.each do |r|
                j.object do
                  j.field("from", r.part)
                  j.field("target", r.target)
                  j.field("attached_template", r.attached_template)
                end
              end
            end
          end
          j.field("fields", pkg.fields.size)
        end
        j.field("findings") do
          j.array do
            verdict.findings.each do |f|
              j.object do
                j.field("id", f.id)
                j.field("title", f.title)
                j.field("severity", f.sev)
                j.field("detail", f.detail)
              end
            end
          end
        end
        j.field("indicators") do
          j.array do
            collect_iocs(doc).each do |i|
              j.object do
                j.field("kind", i.kind)
                j.field("value", i.value)
              end
            end
          end
        end
      end
    end
  end

  def self.markdown(doc : Grim::Rules::Doc, verdict : Grim::Rules::Verdict, path : String) : String
    io = IO::Memory.new
    io << "## grimoire triage — #{File.basename(path)}\n\n"
    io << "| field | value |\n|---|---|\n"
    io << "| verdict | **#{verdict.band}** (#{verdict.score}/100) |\n"
    io << "| format | #{doc.kind} |\n"
    io << "| size | #{doc.size} bytes |\n"
    io << "| sha256 | `#{doc.sha256}` |\n"
    io << "\n### findings\n\n"
    if verdict.findings.empty?
      io << "none.\n"
    else
      io << "| severity | id | detail |\n|---|---|---|\n"
      verdict.findings.sort_by(&.sev).reverse_each do |f|
        io << "| #{SEV_LABEL[f.sev]} | `#{f.id}` | #{f.title}#{f.detail.empty? ? "" : " — " + f.detail.gsub("|", "\\|")} |\n"
      end
    end
    iocs = collect_iocs(doc)
    unless iocs.empty?
      io << "\n### indicators\n\n"
      io << "| kind | value |\n|---|---|\n"
      iocs.each { |i| io << "| #{i.kind} | #{Grim.defang(i.value)} |\n" }
    end
    io << "\n"
    io.to_s
  end
end
