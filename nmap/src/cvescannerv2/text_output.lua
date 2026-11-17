-- SPDX-License-Identifier: GPL-3.0-or-later
-- Text and structured output of the NSE script.  (Layer L6)
--
-- Builds, from the result of one service, the lines printed by Nmap, the
-- lines of the log file and the structured table of the XML output. The
-- result is the table built by service_cves.find_service_cves.
-- No I/O (no network, file or SQL) and no access to state or config:
-- it only formats the values it receives.

local util = require 'cvescannerv2.util'
local confidence = require 'cvescannerv2.confidence'

local fmt = util.fmt
local LEVEL_LABEL = confidence.LEVEL_LABEL

local M = {}

-- Human text of each service warning code.
local WARNING_TEXT = {
  distro_backport = 'distro_backport - fixes may be backported by the distro',
}

-- CVSS versions in display order, newest first.
local CVSS_VERSIONS = { 'v4', 'v3', 'v2' }


--- Return the CVSS scores as text: 'v4:9.3 v3:9.8 v2:7.5', '-' if none.
-- Only the versions present are shown, newest first, with one decimal.
function M.cvss_text(cvss)
  local parts = {}
  for _, ver in ipairs(CVSS_VERSIONS) do
    if cvss[ver] ~= nil then
      parts[#parts + 1] = fmt('%s:%.1f', ver, cvss[ver])
    end
  end
  if #parts == 0 then return '-' end
  return table.concat(parts, ' ')
end

--- Return the exploit flags of a CVE entry: 'EDB MSF', 'EDB', 'MSF' or '-'.
function M.exploit_text(cve)
  local parts = {}
  if #cve.exploitdb > 0 then parts[#parts + 1] = 'EDB' end
  if #cve.metasploit > 0 then parts[#parts + 1] = 'MSF' end
  if #parts == 0 then return '-' end
  return table.concat(parts, ' ')
end

-- Product text: 'product version', with the vendor when it differs from
-- the product and the update when it is not '*'.
local function product_text(result)
  local text = fmt('%s %s', result.product, result.version)
  if result.vendor ~= result.product then
    text = result.vendor .. ' ' .. text
  end
  if result.update ~= nil then
    text = text .. ' update ' .. result.update
  end
  return text
end


-- Counts line: 'CVEs: 64  high: 60  medium: 3  low: 1'.
local function counts_text(counts)
  return fmt('CVEs: %d  high: %d  medium: %d  low: %d', counts.total,
    counts.high, counts.medium, counts.low)
end


-- Warning lines of a service result, with the given prefix.
local function warning_lines(result, prefix)
  local lines = {}
  for _, warning in ipairs(result.warnings) do
    lines[#lines + 1] = prefix .. 'warning: '
        .. (WARNING_TEXT[warning] or warning)
  end
  return lines
end


-- Return the visible CVE entries in order, at most limit of them.
local function visible_cves(result, limit)
  local list = {}
  for _, cve in ipairs(result.cves) do
    if cve.visible then
      if limit ~= nil and #list >= limit then break end
      list[#list + 1] = cve
    end
  end
  return list
end


-- Last line of the Nmap table: what is hidden and where the full list is.
-- Returns nil when nothing is hidden.
local function hidden_line(result, cfg)
  local over = result.counts.shown - cfg.maxcve
  local below = result.counts.total - result.counts.shown
  local parts = {}
  if over > 0 then
    parts[#parts + 1] = fmt('+%d more (maxcve=%d)', over, cfg.maxcve)
  end
  if below > 0 then
    parts[#parts + 1] = fmt('%d below minconf=%s', below, cfg.minconf)
  end
  if #parts == 0 then return nil end
  return table.concat(parts, '; ') .. '. Full list: ' .. cfg.json
end


--- Return the lines Nmap prints for one service result.
-- cfg holds maxcve, minconf and json (the JSON report path).
function M.nmap_lines(result, cfg)
  local lines = {
    fmt('%s (%s)  source: %s', product_text(result), result.cpe,
      result.version_source or '-'),
    counts_text(result.counts),
  }
  for _, line in ipairs(warning_lines(result, '')) do
    lines[#lines + 1] = line
  end
  local shown = visible_cves(result, cfg.maxcve)
  if #shown > 0 then
    lines[#lines + 1] = fmt('  %-16s %-5s %-9s %s', 'CVE', 'CONF',
      'EXPLOITS', 'CVSS')
  end
  for _, cve in ipairs(shown) do
    lines[#lines + 1] = fmt('  %-16s %-5s %-9s %s', cve.id,
      LEVEL_LABEL[cve.confidence], M.exploit_text(cve), M.cvss_text(cve.cvss))
  end
  local hidden = hidden_line(result, cfg)
  if hidden ~= nil then lines[#lines + 1] = hidden end
  return lines
end

--- Return the structured table of one service result for XML output.
-- Holds the visible CVEs up to cfg.maxcve; cvss keeps the versions present.
function M.structured_output(result, cfg)
  local cves = {}
  for _, cve in ipairs(visible_cves(result, cfg.maxcve)) do
    local cvss = {}
    for _, ver in ipairs(CVSS_VERSIONS) do cvss[ver] = cve.cvss[ver] end
    cves[#cves + 1] = {
      id = cve.id,
      confidence = cve.confidence,
      cvss = cvss
    }
  end
  return {
    product = result.product,
    version = result.version,
    source = result.version_source,
    counts = {
      total = result.counts.total,
      high = result.counts.high,
      medium = result.counts.medium,
      low = result.counts.low
    },
    cves = cves,
  }
end

-- Text of the OS context: 'linux (nmap)' or '-'.
local function os_text(os_context)
  if os_context == nil or os_context.family == nil then return '-' end
  return fmt('%s (%s)', os_context.family, os_context.source or '-')
end


-- Log lines of the exploits of one CVE entry, indented under it.
local function exploit_lines(cve)
  local lines = {}
  for _, module in ipairs(cve.metasploit) do
    lines[#lines + 1] = fmt('      MSF  %s', module)
  end
  for _, exploit in ipairs(cve.exploitdb) do
    local line = fmt('      EDB  %s  %s', exploit.id, exploit.url)
    if exploit.name ~= nil then line = line .. '  ' .. exploit.name end
    lines[#lines + 1] = line
  end
  return lines
end


--- Return the log lines of one service result.
-- ctx holds ip, port_proto, service and, for a cached service, cached_from
-- (the 'ip port/proto' where the same result was first reported).
function M.log_lines(result, ctx)
  local lines = {
    fmt('[%s %s %s] %s', ctx.ip, ctx.port_proto, ctx.service or '-',
      product_text(result)),
  }
  if ctx.cached_from ~= nil then
    lines[#lines + 1] = '  cached: same result as ' .. ctx.cached_from
    return lines
  end
  lines[#lines + 1] = fmt('  cpe: %s  source: %s  os: %s', result.cpe,
    result.version_source or '-', os_text(result.os_context))
  lines[#lines + 1] = '  ' .. counts_text(result.counts)
  for _, line in ipairs(warning_lines(result, '  ')) do
    lines[#lines + 1] = line
  end
  for _, cve in ipairs(visible_cves(result)) do
    local reasons = #cve.reasons > 0 and table.concat(cve.reasons, ', ')
        or '-'
    lines[#lines + 1] = fmt('  %-15s %-5s %-20s %s', cve.id,
      LEVEL_LABEL[cve.confidence], M.cvss_text(cve.cvss), reasons)
    for _, line in ipairs(exploit_lines(cve)) do
      lines[#lines + 1] = line
    end
  end
  return lines
end

--- Return the log header lines. args holds minconf, maxcve and db.
function M.log_header(script_version, timestamp, args)
  return {
    fmt('=== cvescannerv2 %s  %s ===', script_version, timestamp),
    fmt('args: minconf=%s maxcve=%s db=%s', args.minconf, args.maxcve,
      args.db),
    '',
  }
end

--- Return the log footer line. totals holds hosts, services and cves.
function M.log_footer(totals)
  return {
    fmt('=== end  hosts: %d  services: %d  CVEs: %d ===', totals.hosts,
      totals.services, totals.cves),
  }
end

return M
