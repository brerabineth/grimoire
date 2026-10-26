require "./common"
require "./rules"
require "./report"
require "./forge"
require "./selftest"

# grimoire — document triage. reads the spells, executes nothing.
module Grim::Entry
  USAGE = <<-USAGE
  grimoire v#{Grim::VERSION} — static triage for hostile documents

  usage:
    grimoire [options] <file> [file...]     triage documents
    grimoire spells <file>                  recover and print macro source
    grimoire carves <file>                  list embedded artifacts by offset
    grimoire ioc <file>                     indicators only (tsv)
    grimoire forge <scenario> <outdir>      build a deterministic fixture
    grimoire rules                          print the rule catalog
    grimoire selftest                       run the built-in test battery

  options:
    --json          machine output (single-line json)
    --md            markdown report
    --color         force ansi color (off when not a tty; NO_COLOR honored)
    --min-score N   recompute verdict from findings scoring at or above N

  scenarios: #{Grim::Forge::SCENARIOS.join(", ")}

  exit codes: 0 clean, 1 watch, 3 suspicious, 10 hostile, 2 usage/error
  nothing executes. nothing leaves the machine.
  USAGE

  def self.run(argv : Array(String)) : Int32
    json_mode = false
    md_mode = false
    force_color = false
    min_score = 0
    files = [] of String
    cmd : String? = nil
    rest = [] of String

    i = 0
    while i < argv.size
      a = argv[i]
      case a
      when "--json"     then json_mode = true
      when "--md"       then md_mode = true
      when "--color"    then force_color = true
      when "--min-score" then
        i += 1
        return usage_error("--min-score needs a number") unless i < argv.size
        begin
          min_score = argv[i].to_i
        rescue
          return usage_error("--min-score needs a number")
        end
      when "spells", "carves", "ioc", "forge", "rules", "selftest", "help", "--help", "-h"
        cmd = a
      else
        if a.starts_with?("-") && a.size > 2
          return usage_error("unknown option #{a}")
        end
        if cmd && %w(spells carves ioc forge).includes?(cmd)
          rest << a
        else
          files << a
        end
      end
      i += 1
    end

    use_color = force_color || (STDOUT.tty? && !ENV.has_key?("NO_COLOR"))

    case cmd
    when "help", "--help", "-h"
      puts USAGE
      return 2
    when "rules"
      puts rules_text
      return 0
    when "selftest"
      return Grim::Selftest.run
    when "forge"
      return usage_error("forge needs <scenario> <outdir>") unless rest.size == 2
      scenario, outdir = rest[0], rest[1]
      unless Grim::Forge::SCENARIOS.includes?(scenario)
        return usage_error("unknown scenario #{scenario} (#{Grim::Forge::SCENARIOS.join(", ")})")
      end
      begin
        path = Grim::Forge.forge_dir(scenario, outdir)
      rescue e : Exception
        return usage_error("forge failed: #{e.message}")
      end
      puts path
      return 0
    when "spells", "carves", "ioc"
      return usage_error("#{cmd} needs one file") unless rest.size == 1
      path = rest[0]
      data = read_doc(path)
      return 2 if data.nil?
      doc = Grim::Rules.build(data)
      case cmd
      when "spells" then puts Grim::Report.spells(doc, path, use_color)
      when "carves" then puts Grim::Report.carves(doc, path, use_color)
      when "ioc"    then puts Grim::Report.ioc_list(doc, path, use_color)
      end
      return 0
    end

    return usage_error("no document given") if files.empty?
    files.each do |path|
      data = read_doc(path)
      if data.nil?
        STDERR.puts "grimoire: cannot read #{File.basename(path)}"
        return 2 if files.size == 1
        next
      end
      doc = Grim::Rules.build(data)
      verdict = Grim::Rules.verdict(doc)
      if min_score > 0
        kept = verdict.findings.select { |f| f.sev >= min_score }
        s2, force2 = Grim::Rules.score(kept)
        verdict = Grim::Rules::Verdict.new(s2, Grim::Rules.band_for(s2, force2), force2, kept)
      end
      if json_mode
        puts Grim::Report.json(doc, verdict, path)
      elsif md_mode
        puts Grim::Report.markdown(doc, verdict, path)
      else
        puts Grim::Report.terminal(doc, verdict, path, use_color, min_score == 0)
      end
      code = Grim::Rules::BAND_EXIT[verdict.band].not_nil!
      return code if files.size == 1
    end
    0
  end

  private def self.read_doc(path : String) : Bytes?
    return nil unless File.file?(path)
    File.read(path).to_slice
  rescue
    nil
  end

  private def self.usage_error(msg : String) : Int32
    STDERR.puts "grimoire: #{msg}"
    STDERR.puts "try 'grimoire help'"
    2
  end

  private def self.rules_text : String
    io = IO::Memory.new
    io << "grimoire v#{Grim::VERSION} — rule catalog\n\n"
    io << "verdict bands: clean <10 <= watch <25 <= suspicious <60 <= hostile\n"
    io << "forced hostile: " << Grim::Rules::FORCE_HOSTILE.join(", ") << "\n\n"
    io << "surface        id                          sev\n"
    io << "-" * 62 << "\n"
    catalog.each do |id, sev|
      io << sprintf("%-14s %-27s %d\n", catalog_area(id), id, sev)
    end
    io.to_s
  end

  private def self.catalog_area(id : String) : String
    id.split(".")[0]? || "?"
  end

  def self.catalog : Array(Tuple(String, Int32))
    cat = [] of Tuple(String, Int32)
    base = [
      {"doc.remote.template", 4}, {"doc.external.link", 2}, {"doc.external.file", 1},
      {"doc.activex", 2}, {"doc.embedded.objects", 2}, {"doc.dde.fields", 3},
      {"doc.dde.executes", 4}, {"doc.fields.remote", 2}, {"doc.updatefields", 2},
      {"doc.protection", 1}, {"vba.project", 2}, {"vba.autoexec", 3},
      {"vba.autoexec.downloader", 4}, {"vba.proc.inject", 4},
      {"vba.obfuscation.chr", 2}, {"vba.obfuscation.split", 1},
      {"vba.decoded.chr-chain", 3}, {"vba.decoded.base64", 3},
      {"vba.decoded.hex-text", 3}, {"vba.decoded.hex-blob", 3},
      {"vba.decoded.strreverse", 3}, {"vba.decoded.hit", 3},
      {"vba.entropy", 1}, {"vba.exec", 2}, {"vba.net", 3}, {"vba.drop", 4},
      {"vba.persist", 4}, {"vba.evade", 2}, {"vba.proc", 3},
      {"xlm.sheets", 3}, {"xlm.exec.spell", 4},
      {"zip.encrypted.parts", 3},
      {"ole.native.executable", 4}, {"ole.native.embedded", 2},
      {"ole.objectpool", 2},
      {"rtf.embedded.ole", 2}, {"rtf.embedded.pe", 4}, {"rtf.embedded.zip", 3},
      {"rtf.embedded.blob", 1}, {"rtf.package.object", 3},
      {"rtf.equation.exploit", 4}, {"rtf.objupdate", 1}, {"rtf.depth", 2},
      {"rtf.bigbin", 2},
      {"one.container", 2},
      {"carve.pe", 3}, {"carve.ole", 2}, {"carve.zip", 1}, {"carve.lnk", 3},
      {"carve.pdf", 1},
    ]
    base.each { |id, sev| cat << {id, sev} }
    cat
  end
end
