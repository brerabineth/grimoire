require "./rites/common"
require "./rites/cfb"
require "./rites/vba"
require "./rites/vbascan"
require "./rites/ooxml"
require "./rites/rtf"
require "./rites/carver"
require "./rites/rules"
require "./rites/forge"
require "./rites/report"
require "./rites/selftest"
require "./rites/entry"

exit Grim::Entry.run(ARGV)
