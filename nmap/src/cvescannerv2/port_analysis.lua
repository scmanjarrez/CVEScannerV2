-- SPDX-License-Identifier: GPL-3.0-or-later
-- Analysis of the matches of one port for cvescannerv2.  (Layer L8)
--
-- Walks the matches of a port, looks up the vulnerabilities of each
-- service through the cache and feeds the report, the render and the log.
-- No direct network or file I/O. Reads config filters and reads and writes
-- state.service_cache.

local config = require 'cvescannerv2.config'
local log = require 'cvescannerv2.log'
local render = require 'cvescannerv2.text_output'
local report = require 'cvescannerv2.json_report'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local version = require 'cvescannerv2.version'
local vulns = require 'cvescannerv2.service_cves'
local stdnse = require 'stdnse'

local M = {}

local fmt = util.fmt
local parse_cpe_version = version.parse_cpe_version
local display_version = version.display_version
local log_service = log.log_service
local log_separator = log.log_separator
local service_lines = render.service_lines
local find_service_cves = vulns.find_service_cves


-- Key of the per-service context that changes the output of a scan.
local function context_key(scan_ctx)
  local os_ctx = scan_ctx.os or {}
  return fmt('%s|%s|%s|%s|%s', tostring(scan_ctx.version_source),
    tostring(os_ctx.family), tostring(os_ctx.distro),
    tostring(os_ctx.source), tostring(scan_ctx.backport))
end


-- Cache key of one service. Unknown OS also keys by host IP, so a probe
-- result is never reused across hosts.
local function service_cache_key(host, vendor, product, ver_text, update,
    scan_ctx)
  local key = fmt('%s|%s|%s|%s|%s', vendor, product, ver_text, update,
    context_key(scan_ctx))
  if scan_ctx.os.family == nil then key = key .. '|' .. host.ip end
  return key
end


-- True when the config filter selects this product and version.
local function is_selected_service(product, version_str)
  local svc, ver = config.service, config.version
  if svc == 'all' and ver == 'all' then
    return true
  end
  if svc ~= 'all' and ver ~= 'all' then
    return product == svc and version_str == ver
  end
  if svc ~= 'all' then
    return product == svc
  end
  return version_str == ver
end


-- Scans a service missing from the cache and stores the result.
-- Returns the vulnerability lines of the service.
local function scan_uncached_service(host, port, cpe, vendor, product,
    ver_text, update, info, scan_ctx, cache_key)
  local cve_lines, meta = find_service_cves(host, port, cpe, vendor,
    product, info, scan_ctx)
  if meta.os_context.family ~= scan_ctx.os.family then
    -- An OS probe changed the context: key by the new one.
    cache_key = service_cache_key(host, vendor, product, ver_text, update,
      { os = meta.os_context,
        backport = scan_ctx.backport,
        version_source = scan_ctx.version_source })
  end
  local cve_count = table.remove(cve_lines, 1)
  if cve_count > 0 then
    local serv_fmt = fmt('%s/%s', port.number, port.protocol)
    report.set_total(host.ip, serv_fmt, cve_count)
    cve_lines = service_lines(vendor, product, ver_text, update, cve_count,
      meta, cve_lines)
    stdnse.verbose(2, "Caching " .. product .. "|" ..
      ver_text .. "|" .. update .. " vulnerabilities.")
    state.service_cache[cache_key] = {
      cve_count = cve_count,
      lines = cve_lines,
      meta = meta,
    }
  end
  return cve_lines
end


-- Reuses a cached service: reports it and returns its vulnerability lines.
local function report_cached_service(host, port, cpe, vendor, product,
    ver_text, update, cache)
  log.write("[+] cves: cached")
  if cache.cve_count > 0 then
    local port_proto = fmt('%s/%s', port.number, port.protocol)
    report.ensure_port(host.ip, port_proto)
    report.add_service(host.ip, port_proto,
      {
        name = port.service,
        cpe = cpe,
        vendor = vendor,
        product = product,
        version = ver_text,
        vupdate = update,
        version_source = cache.meta.version_source,
        os_context = cache.meta.os_context,
        warnings = cache.meta.warnings,
        summary = cache.meta.summary,
        vulnerabilities = {
          ['total'] = cache.cve_count,
          ['info'] = 'cache'
        }
      }
    )
  end
  log_separator()
  stdnse.verbose(2, "Using cached " .. product .. "|" ..
    ver_text .. "|" .. update .. " vulnerabilities.")
  return cache.lines
end


-- Returns the vulnerability lines of a service, from cache when possible.
local function service_cve_lines(host, port, cpe, vendor, product, ver_text,
    update, info, scan_ctx)
  local cache_key = service_cache_key(host, vendor, product, ver_text,
    update, scan_ctx)
  if not state.service_cache[cache_key] then
    return scan_uncached_service(host, port, cpe, vendor, product,
      ver_text, update, info, scan_ctx, cache_key)
  end
  return report_cached_service(host, port, cpe, vendor, product, ver_text,
    update, state.service_cache[cache_key])
end


-- Appends the vulnerability lines of a service once per vendor and version.
local function add_lines(vulns_out, logged, vendor, product, ver_text,
    update, cve_lines)
  local log_key = fmt("%s|%s|%s|%s", vendor, product, ver_text, update)
  if cve_lines ~= nil and #cve_lines > 0 and logged[log_key] == nil then
    logged[log_key] = 1
    for _, value in pairs(cve_lines) do
      table.insert(vulns_out, value)
    end
    table.insert(vulns_out, "")
  end
end


-- Handles one CPE and version pair of the matches of a port.
local function analyze_match(host, port, scan_ctx, origin, cpe, version_str,
    vulns_out, logged)
  stdnse.verbose(2, fmt("cpe => %s | version => %s", cpe, version_str))
  local vendor, product, info, source = parse_cpe_version(cpe, version_str)
  local version_source = source
  if origin ~= 'nmap' then
    version_source = origin
  end
  if not is_selected_service(product, version_str) then
    return
  end
  stdnse.verbose(2, fmt("product => %s | version => %s", product,
    version_str))
  if info == nil then
    return
  end
  log_service(host, port, cpe, vendor, product, info)
  local ver_text, update = display_version(info)
  local svc_ctx = {
    os = scan_ctx.os,
    backport = scan_ctx.backport,
    version_source = version_source,
  }
  local cve_lines = service_cve_lines(host, port, cpe, vendor, product,
    ver_text, update, info, svc_ctx)
  add_lines(vulns_out, logged, vendor, product, ver_text, update, cve_lines)
end


--- Return the vulns of a port's matches; scan_ctx has OS and distro data.
local function analyze_port(host, port, matches, scan_ctx)
  local vulns_out = {}
  local logged = {}
  for origin, data in pairs(matches['data']) do
    for cpe, versions in pairs(data) do
      for version_str, _ in pairs(versions) do
        analyze_match(host, port, scan_ctx, origin, cpe, version_str,
          vulns_out, logged)
      end
    end
  end
  return vulns_out
end

M.analyze_port = analyze_port

return M
