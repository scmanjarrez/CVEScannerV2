-- SPDX-License-Identifier: GPL-3.0-or-later
-- Text output of the NSE script.  (Layer L6)
--
-- Builds the lines printed for one service and the CVE rows inside them.
-- No I/O (no network, file or SQL) and no access to state or config:
-- it only formats the values it receives.

local util = require 'cvescannerv2.util'
local confidence = require 'cvescannerv2.confidence'

local fmt = util.fmt
local LEVEL_LABEL = confidence.LEVEL_LABEL

local M = {}

-- Human text of each service warning code.
local WARNING_TEXT = {
  distro_backport = 'CVEs pueden estar parcheadas por backport',
}

-- One CVE row of the service table, with the columns of the table header.
function M.cve_row(id, level, cvssv2, cvssv3, exploitdb, metasploit)
  return fmt("\t%-20s\t%-6s\t%-5s\t%-5s\t%-10s\t%-10s",
    id, LEVEL_LABEL[level],
    cvssv2, cvssv3 or "-",
    exploitdb == 1 and "Yes" or "No",
    metasploit == 1 and "Yes" or "No"
  )
end

-- Prepend the service header lines to the CVE rows of one service.
function M.service_lines(vendor, product, ver_text, update, cve_count,
    meta, rows)
  local lines = {
    fmt("vendor: %s", vendor),
    fmt("product: %s", product),
    fmt("version: %s", ver_text),
    fmt("vupdate: %s", update),
    fmt("version_source: %s", meta.version_source or '-'),
  }
  for _, warning in ipairs(meta.warnings) do
    table.insert(lines, fmt("warning: %s", WARNING_TEXT[warning] or warning))
  end
  local total = ''
  if meta.shown < cve_count then total = fmt(' (total %d)', cve_count) end
  table.insert(lines, fmt("cves: %d%s", meta.shown, total))
  table.insert(lines, fmt("\t%-20s\t%-6s\t%-5s\t%-5s\t%-10s\t%-10s",
    "CVE ID", "Conf", "CVSSv2", "CVSSv3", "ExploitDB", "Metasploit"))
  for _, row in ipairs(rows) do table.insert(lines, row) end
  return lines
end

return M
