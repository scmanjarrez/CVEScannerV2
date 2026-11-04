-- Text output of the NSE script.
--
-- Builds the lines printed for one service and the CVE rows inside them.
-- Pure formatting: nothing here touches the shared state.

local util = require 'cvescannerv2.util'
local confidence = require 'cvescannerv2.confidence'

local fmt = util.fmt
local CONF_LABEL = confidence.CONF_LABEL

local M = {}

-- Human text of each service warning code.
local WARNING_TEXT = {
  distro_backport = 'CVEs pueden estar parcheadas por backport',
}
M.WARNING_TEXT = WARNING_TEXT

-- One CVE row of the service table, with the columns of the table header.
function M.cve_row(id, level, cvssv2, cvssv3, exploitdb, metasploit)
  return fmt("\t%-20s\t%-6s\t%-5s\t%-5s\t%-10s\t%-10s",
    id, CONF_LABEL[level],
    cvssv2, cvssv3 or "-",
    exploitdb == 1 and "Yes" or "No",
    metasploit == 1 and "Yes" or "No"
  )
end

-- Prepend the service header lines to the CVE rows of one service.
function M.service_lines(vendor, product, v, vu, nvulns, meta, rows)
  local lines = {
    fmt("vendor: %s", vendor),
    fmt("product: %s", product),
    fmt("version: %s", v),
    fmt("vupdate: %s", vu),
    fmt("version_source: %s", meta.version_source or '-'),
  }
  for _, warning in ipairs(meta.warnings) do
    table.insert(lines, fmt("warning: %s", WARNING_TEXT[warning] or warning))
  end
  local total = ''
  if meta.shown < nvulns then total = fmt(' (total %d)', nvulns) end
  table.insert(lines, fmt("cves: %d%s", meta.shown, total))
  table.insert(lines, fmt("\t%-20s\t%-6s\t%-5s\t%-5s\t%-10s\t%-10s",
    "CVE ID", "Conf", "CVSSv2", "CVSSv3", "ExploitDB", "Metasploit"))
  for _, row in ipairs(rows) do table.insert(lines, row) end
  return lines
end

return M
