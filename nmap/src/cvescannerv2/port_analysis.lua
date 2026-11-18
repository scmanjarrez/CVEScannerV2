-- SPDX-License-Identifier: GPL-3.0-or-later
-- Analysis of the matches of one port for cvescannerv2.  (Layer L8)
--
-- Walks the matches of a port, gets the result of each service from the
-- cache or from service_cves, and feeds the JSON report, the log and the
-- Nmap output. No direct network or file I/O. Reads config filters and
-- reads and writes state.service_cache and state.totals.

local config = require 'cvescannerv2.config'
local log = require 'cvescannerv2.log'
local mssql_build = require 'cvescannerv2.mssql_build'
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


-- Scans a service missing from the cache and stores the result when it has
-- CVEs. Returns the result and the origin of the scan.
local function scan_uncached_service(host, port, cpe, vendor, product,
                                     ver_text, update, info, scan_ctx, cache_key)
  local result = find_service_cves(host, port, cpe, vendor, product, info,
    scan_ctx)
  if result.os_context.family ~= scan_ctx.os.family then
    -- An OS probe changed the context: key by the new one.
    cache_key = service_cache_key(host, vendor, product, ver_text, update,
      {
        os = result.os_context,
        backport = scan_ctx.backport,
        version_source = scan_ctx.version_source
      })
  end
  local origin = fmt('%s %s/%s', host.ip, port.number, port.protocol)
  if result.counts.total > 0 then
    stdnse.verbose(2, "Caching " .. product .. "|" ..
      ver_text .. "|" .. update .. " vulnerabilities.")
    state.service_cache[cache_key] = { result = result, origin = origin }
  end
  return result, nil
end


-- Return the result of a service, from the cache when possible. The second
-- value is the origin of the cached result, or nil when it was just scanned.
local function service_result(host, port, cpe, vendor, product, ver_text,
                              update, info, scan_ctx)
  local cache_key = service_cache_key(host, vendor, product, ver_text,
    update, scan_ctx)
  local cache = state.service_cache[cache_key]
  if cache == nil then
    return scan_uncached_service(host, port, cpe, vendor, product,
      ver_text, update, info, scan_ctx, cache_key)
  end
  stdnse.verbose(2, "Using cached " .. product .. "|" ..
    ver_text .. "|" .. update .. " vulnerabilities.")
  return cache.result, cache.origin
end


-- Key of a result within one port: vendor, product, version and update.
local function result_key(result)
  return fmt('%s|%s|%s|%s', result.vendor, result.product,
    result.version, tostring(result.update))
end


-- Add the result of a service to the report, the log and the totals. Called
-- once per service and port: analyze_match skips repeated results.
local function record_service(host, port, result, origin)
  local total = result.counts.total
  if total > 0 then
    report.add_service(host.ip, port, result, origin ~= nil)
  end
  log.write_lines(render.log_lines(result, {
    ip = host.ip,
    port_proto = fmt('%s/%s', port.number, port.protocol),
    service = port.service,
    cached_from = origin,
  }))
  if state.totals then
    state.totals.services = state.totals.services + 1
    state.totals.cves = state.totals.cves + total
  end
end


-- Add the Nmap lines and the structured rows of a result to out and mark
-- its key in out.logged. Results without CVEs add nothing and are not marked.
local function add_output(out, cfg, result)
  if result.counts.total == 0 then return end
  out.logged[result_key(result)] = true
  out.structured[#out.structured + 1] = render.structured_output(result, cfg)
  if #out.lines > 0 then out.lines[#out.lines + 1] = "" end
  for _, line in ipairs(render.nmap_lines(result, cfg)) do
    out.lines[#out.lines + 1] = line
  end
end


-- Handles one CPE and version pair of the matches of a port. selected tells
-- whether the original CPE of the pair passes the config filter, so a
-- refined CPE is kept when its original product was selected.
local function analyze_match(host, port, scan_ctx, origin, cpe, version_str,
                             selected, out, cfg)
  stdnse.verbose(2, fmt("cpe => %s | version => %s", cpe, version_str))
  local vendor, product, info, source = parse_cpe_version(cpe, version_str)
  local version_source = source
  if origin ~= 'nmap' then
    version_source = origin
  end
  if not (selected or is_selected_service(product, version_str)) then
    return
  end
  stdnse.verbose(2, fmt("product => %s | version => %s", product,
    version_str))
  if info == nil then
    return
  end
  local ver_text, update = display_version(info)
  local svc_ctx = {
    os = scan_ctx.os,
    backport = scan_ctx.backport,
    version_source = version_source,
  }
  local result, cached_from = service_result(host, port, cpe, vendor,
    product, ver_text, update, info, svc_ctx)
  -- Only one entry per service and port: a repeated result is skipped.
  if out.logged[result_key(result)] ~= nil then return end
  record_service(host, port, result, cached_from)
  add_output(out, cfg, result)
end


-- Keys of t sorted alphabetically, with first (when present) placed first.
---@param t table<string, any>
---@param first string?
---@return string[]
local function sorted_keys(t, first)
  local keys = {}
  for k in pairs(t) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b)
    if a == first or b == first then return a == first and b ~= first end
    return a < b
  end)
  return keys
end


--- Return the structured rows and the Nmap lines of a port's matches.
-- scan_ctx has the OS and distro data. Returns two lists. The dedupe state
-- (out.logged) is local to this call, so each port starts empty.
local function analyze_port(host, port, matches, scan_ctx)
  local out = { structured = {}, lines = {}, logged = {} }
  local cfg = {
    maxcve = config.maxcve,
    minconf = config.minconf,
    json = config.json,
  }
  local data = matches['data']
  for _, origin in ipairs(sorted_keys(data, 'nmap')) do
    local cpes = data[origin]
    for _, cpe in ipairs(sorted_keys(cpes)) do
      local versions = cpes[cpe]
      for _, version_str in ipairs(sorted_keys(versions)) do
        local _, original_product = parse_cpe_version(cpe, version_str)
        local selected = is_selected_service(original_product, version_str)
        for _, refined in ipairs(mssql_build.refine(cpe, version_str)) do
          analyze_match(host, port, scan_ctx, origin, refined, version_str,
            selected, out, cfg)
        end
      end
    end
  end
  return out.structured, out.lines
end

M.analyze_port = analyze_port

return M
