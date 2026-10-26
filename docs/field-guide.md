# field guide — how grimoire thinks

notes on the rule surface, the scoring model, and the tricks each check is
hunting. read this once and the terminal output stops being noise.

## the model

every document becomes a `Doc` record: container kind, sha256, whatever
parsed cleanly, whatever the carver found. findings are emitted by surface
(oopackage / olefile / rtffile / container), each with a rule id, a title
and a severity from 1 (low) to 4 (critical).

scoring is deliberately boring: each distinct rule adds `severity x 6`,
capped at 24 per rule, total capped at 100. bands:

```
clean      score < 10            exit 0
watch      score < 25            exit 1
suspicious score < 60            exit 3
hostile    score >= 60           exit 10
```

a short list of combinations **forces hostile** no matter the arithmetic:

| id | why it is not negotiable |
|---|---|
| `vba.autoexec.downloader` | trigger + network fetch + drop/exec in one module is a loader, full stop |
| `rtf.equation.exploit` | Equation.3 objects are RCE-on-open, not a curiosity |
| `ole.native.executable` | Ole10Native carrying `.exe/.scr/.js/...` is a dropper with extra steps |
| `doc.dde.executes` | DDE fields spawning cmd/powershell/mshta are code execution by design |
| `vba.proc.inject` | WriteProcessMemory/VirtualAlloc/RtlMoveMemory in VBA is shellcode staging |
| `xlm.exec.spell` | XLM `EXEC`/`CALL` in a macro sheet is a loader wearing a spreadsheet |

## the macro-less surface (why "no vba" means nothing)

the campaigns that dominated 2026 stopped shipping macros at all. the
document only *points* at the payload:

- **remote template injection** — `word/_rels/settings.xml.rels` gains a
  relationship of type `attachedTemplate` with `TargetMode="External"` and
  an http/UNC target. Word fetches it on open and the `.dotm` carries the
  macros. the docx itself is clean by every naive check. rule:
  `doc.remote.template` (sev 4).
- **DDE / DDEAUTO** — field instructions that run a command instead of
  linking data. rules: `doc.dde.fields`, `doc.dde.executes`.
- **XLM / Excel 4.0** — `xl/macrosheets/sheetN.xml` with `=EXEC(...)`,
  `=CALL(...)`. no vbaProject.bin anywhere. rules: `xlm.sheets`,
  `xlm.exec.spell`.
- **embedded objects** — `word/embeddings/*.bin` (OLE), activeX controls,
  `\1Ole10Native` streams that disclose the original file name and drop
  path of whatever was packaged. rules: `doc.embedded.objects`,
  `doc.activex`, `ole.native.*`.
- **rtf containers** — `\objdata` hex hiding a full OLE or PE,
  `\objclass Equation.3` (CVE-2017-11882 lineage), `{\*\template URL}`,
  group nesting deep enough to eat scanner stacks (`rtf.depth`).
- **package metadata** — the SummaryInformation `template` field can carry
  a URL too; `doc.remote.template` fires from metadata as well.

## the vba layer

when there *is* a vba project, grimoire recovers real source text:
CFB parse → `VBA/dir` stream → MS-OVBA decompression → module streams at
their recorded text offsets. on top of the source:

- **triggers** — AutoOpen/Workbook_Open/Document_Close and friends, plus
  the control-event tricks (InkPicture_Painted and cousins) that fire
  without a user double-click.
- **census** — Shell/WScript.Shell, MSXML2/WinHttp fetch, ADODB.Stream
  drops, RegWrite persistence, Environ probing, kernel32 memory APIs,
  LOLBin names (certutil, bitsadmin, rundll32...).
- **deobfuscation** — `Chr()/ChrW/ChrB` chains are decoded into
  contiguous strings; `StrReverse("...")` literals are reversed; base64
  and hex blobs are decoded when they turn out printable. **every decoded
  payload is re-scanned with the same census**, and hits are reported as
  `vba.decoded.hit` with the marker that tripped.
- **shape** — entropy per module, Chr-call density, line-continuation
  assembly.

## carving

for containers the readers cannot fully parse — OneNote revision stores,
unknown blobs, the tail of anything — a magic sweep reports embedded MZ/PE
(with a header sanity check so `"MZ"` strings in documents do not lie),
PK zips, OLE compound files, PDFs, LNK shortcuts, ELF images, with file
offsets. zip hits inside an ooxml package are suppressed (the package is
itself a zip); everything else reports.

## hygiene guarantees

- every rendering path masks credential-shaped literals
  (`github_pat_`, `ghp_`, `AKIA`/`ASIA`, `sk-`, `xox*`, PEM headers)
  before a single byte reaches the terminal, json or markdown
- indicators are defanged (`hxxp[:]//203[.]0[.]113[.]7`) in every output
- paths are only ever what the operator typed; the tool emits file names,
  never host directories
- `selftest` runs the full 84-check battery from the binary alone — if a
  release binary passes selftest on your machine, it is the same logic
  that shipped

## reading the exit code in a pipeline

```
grimoire --json ./attachments/*.docx | ...   # machine readable, one line per file
grimoire ./suspicious.docm || echo "triage says: act on it"
# exit 10 -> hostile; 3 -> suspicious; 1 -> watch; 0 -> clean
```

CI usage: run grimoire over a directory of attachments and alert on any
non-zero exit below 3 (watch) or on 10 only, depending on appetite.
