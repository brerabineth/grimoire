# grimoire

**static triage for hostile documents.** reads the spells inside office files
before anyone opens them. one binary. nothing executes, nothing leaves the
machine.

> most documents are just paper. the interesting ones are books of spells —
> a macro that fires on open, a template fetched from a stranger's server, a
> package object pretending to be an invoice. grimoire reads the book so you
> do not have to open it.

## why

vba macros are blocked by default almost everywhere now, and attackers moved
with the block. the 2026 wave is **macro-less**: docx files whose settings
pull a remote template (T1221), rtf with DDEAUTO field codes, Excel 4.0/XLM
sheets, Equation-class objects, Ole10Native packages with a renamed `.scr`
inside. the file on disk looks innocent because the payload is not in it —
it is *referenced* by it. scanners that only look for `vbaProject.bin` miss
the whole class.

grimoire reads both sides: the macro-bearing files **and** the macro-less
tricks that replaced them.

## what it reads

| container | what grimoire looks at |
|---|---|
| docx / docm / xlsm / xlsx / pptx / dotm | part census, external relationships, `attachedTemplate`, DDE field codes, `updateFields`, activeX, embedded objects, XLM macro sheets, `vbaProject.bin` |
| doc / xls / ppt / any OLE2 | full CFB walk (FAT + miniFAT), stream census, SummaryInformation metadata, `\1Ole10Native` embedded-file disclosure, object pools |
| vbaProject.bin | dir-stream parse, MS-OVBA decompression, module source recovery |
| rtf | `\objdata` hex → OLE/PE/zip decode, `\objclass` (Package, Equation.3), DDE/DDEAUTO field codes, `\*\template`, group-depth abuse |
| one (OneNote) / unknown | magic-byte carving: MZ/PE, PK, OLE, PDF, LNK, ELF with offsets |

every recovered VBA module goes through the same analysis: auto-exec
triggers, hostile API census, and a deobfuscation layer that decodes
`Chr()` chains, `StrReverse`, base64 and hex blobs — then **re-scans the
decoded payload**, because encoded trickery is still trickery.

## quick start

```
$ grimoire invoice_summary.docm
  grimoire v0.1.0 — document triage
  file     invoice_summary.docm
  verdict  HOSTILE  score 100/100
  format   ooxml
  ...

  ▸ 5 critical
    · auto-exec + fetch + drop chain
      vba.autoexec.downloader — Mod1 runs on open, downloads and drops
    ...

  indicators (defanged)
       url  hxxp[:]//203[.]0[.]113[.]77:8080/drop[.]bin
```

no macros? still worth reading:

```
$ grimoire policy_update.docx
  verdict  SUSPICIOUS  score 42/100
  ...
  ▸ 1 critical
    · remote template injection (settings.xml.rels)
      doc.remote.template — word/settings.xml fetches hxxp[:]//...relic.dotm on open
```

## commands

```
grimoire <file>...          triage (terminal, json or markdown)
grimoire spells <file>      recover and print macro source
grimoire carves <file>      embedded artifacts by offset
grimoire ioc <file>         indicators only, tsv
grimoire forge <scenario> <outdir>   build a deterministic test fixture
grimoire rules              the rule catalog
grimoire selftest           run the built-in battery anywhere
```

flags: `--json` (single-line), `--md`, `--color`, `--min-score N`.

## exit codes

```
0   clean
1   watch
3   suspicious
10  hostile
2   usage or unreadable input
```

bands: clean <10 ≤ watch <25 ≤ suspicious <60 ≤ hostile. certain
combinations force hostile regardless of score — auto-exec chained with
fetch+drop, DDE fields spawning interpreters, Equation.3 exploit objects,
XLM `EXEC` calls, executable Ole10Native payloads.

## forge

fixtures are generated, not committed. every scenario is byte-stable
(fixed timestamps, fixed deflate, hand-packed CFB) so tests and demos
reproduce exactly:

```
$ grimoire forge macro ./fx
./fx/invoice_summary.docm
$ grimoire forge --help   # scenarios: clean, macro, template, xlm, dde, native, carve
```

the fixtures use lab-safe payloads only — TEST-NET addresses, `.invalid`
domains, junk MZ bodies. nothing alive.

## what it does not do

- no dynamic analysis: nothing runs, no sandbox, no detonation
- no password decryption: encrypted parts are *reported* (that is itself a
  finding), not opened
- no p-code/VBA-stomping recovery: source text only, stomping is reported
  as a gap, not solved
- no network: the tool never dials the IOC hostnames it finds

## building

needs a crystal compiler ≥ 1.14:

```
crystal build --release grimoire.cr -o grimoire
crystal spec          # 19 examples
grimoire selftest     # 84 checks, works from the released binary alone
```

links only base system libraries (libc, libz, openssl, libxml2) — present
on any linux or macOS box. no shards, no vendored anything.

## platform

linux x86-64 and macOS arm64 release binaries ship on the releases page.
source builds work anywhere crystal does.

## the rest of the shelf

grimoire sits next to its siblings: `dirge` reads the email envelope,
`effigy` the shortcut, `husk`/`necropsy` the binaries, `seance` the wire.
the document was the missing shelf. read it before it opens you.

---

MIT — see LICENSE. made for the first hour, by hand.
