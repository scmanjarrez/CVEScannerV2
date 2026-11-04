-- SPDX-License-Identifier: GPL-3.0-or-later
-- Analysis of the matches of one port for cvescannerv2.  (Layer L8)
--
-- Walks the matches of a port, looks up the vulnerabilities of each
-- service through the cache and feeds the report, the render and the log.
-- No direct network or file I/O. Reads config filters and reads and writes
-- state.cache.

local config = require 'cvescannerv2.config'
local log_mod = require 'cvescannerv2.log'
local render = require 'cvescannerv2.render'
local report = require 'cvescannerv2.report'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local version = require 'cvescannerv2.version'
local vulns = require 'cvescannerv2.vulns'
local stdnse = require 'stdnse'

local M = {}

local fmt = util.fmt
local cpe_parser = version.cpe_parser
local correct_version = version.correct_version
local log = log_mod.log
local log_info = log_mod.log_info
local log_separator = log_mod.log_separator
local service_lines = render.service_lines
local vulnerabilities = vulns.vulnerabilities


-- Key of the per-service context that changes the output of a scan.
local function context_key(ctx)
  local os_ctx = ctx.os or {}
  return fmt('%s|%s|%s|%s|%s', tostring(ctx.version_source),
    tostring(os_ctx.family), tostring(os_ctx.distro),
    tostring(os_ctx.source), tostring(ctx.backport))
end


-- Cache key of one service. Unknown OS also keys by host IP, so a probe
-- result is never reused across hosts.
local function service_cache_key(host, vendor, product, v, vu, ctx)
  local key = fmt('%s|%s|%s|%s|%s', vendor, product, v, vu,
    context_key(ctx))
  if ctx.os.family == nil then key = key .. '|' .. host.ip end
  return key
end


-- True when the config filter selects this product and version.
local function selected(product, version_str)
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
local function scan_service(host, port, cpe, vendor, product, v, vu, info,
    vctx, cache_key)
  local tmp_vulns, meta = vulnerabilities(host, port, cpe, vendor,
    product, info, vctx)
  if meta.os_context.family ~= vctx.os.family then
    -- An OS probe changed the context: key by the new one.
    cache_key = service_cache_key(host, vendor, product, v, vu,
      { os = meta.os_context,
        backport = vctx.backport,
        version_source = vctx.version_source })
  end
  local nvulns = table.remove(tmp_vulns, 1)
  if nvulns > 0 then
    local serv_fmt = fmt('%s/%s', port.number, port.protocol)
    report.set_total(host.ip, serv_fmt, nvulns)
    tmp_vulns = service_lines(vendor, product, v, vu, nvulns, meta,
      tmp_vulns)
    stdnse.verbose(2, "Caching " .. product .. "|" ..
      v .. "|" .. vu .. " vulnerabilities.")
    state.cache[cache_key] = { nvulns, tmp_vulns, meta }
  end
  return tmp_vulns
end


-- Reuses a cached service: reports it and returns its vulnerability lines.
local function reuse_cache(host, port, cpe, vendor, product, v, vu, cache)
  log("[+] cves: cached")
  if cache[1] > 0 then
    local port_proto = fmt('%s/%s', port.number, port.protocol)
    report.ensure_port(host.ip, port_proto)
    report.add_service(host.ip, port_proto,
      {
        name = port.service,
        cpe = cpe,
        vendor = vendor,
        product = product,
        version = v,
        vupdate = vu,
        version_source = cache[3].version_source,
        os_context = cache[3].os_context,
        warnings = cache[3].warnings,
        summary = cache[3].summary,
        vulnerabilities = {
          ['total'] = cache[1],
          ['info'] = 'cache'
        }
      }
    )
  end
  log_separator()
  stdnse.verbose(2, "Using cached " .. product .. "|" ..
    v .. "|" .. vu .. " vulnerabilities.")
  return cache[2]
end


-- Returns the vulnerability lines of a service, from cache when possible.
local function service_vulns(host, port, cpe, vendor, product, v, vu, info,
    vctx)
  local cache_key = service_cache_key(host, vendor, product, v, vu, vctx)
  if not state.cache[cache_key] then
    return scan_service(host, port, cpe, vendor, product, v, vu, info,
      vctx, cache_key)
  end
  return reuse_cache(host, port, cpe, vendor, product, v, vu,
    state.cache[cache_key])
end


-- Appends the vulnerability lines of a service once per vendor and version.
local function add_lines(vulns_out, logged, vendor, product, v, vu,
    tmp_vulns)
  local log_key = fmt("%s|%s|%s|%s", vendor, product, v, vu)
  if tmp_vulns ~= nil and #tmp_vulns > 0 and logged[log_key] == nil then
    logged[log_key] = 1
    for _, value in pairs(tmp_vulns) do
      table.insert(vulns_out, value)
    end
    table.insert(vulns_out, "")
  end
end


-- Handles one CPE and version pair of the matches of a port.
local function analyze_match(host, port, ctx, origin, cpe, version_str,
    vulns_out, logged)
  stdnse.verbose(2, fmt("cpe => %s | version => %s", cpe, version_str))
  local vendor, product, info, source = cpe_parser(cpe, version_str)
  local version_source = source
  if origin ~= 'nmap' then
    version_source = origin
  end
  if not selected(product, version_str) then
    return
  end
  stdnse.verbose(2, fmt("product => %s | version => %s", product,
    version_str))
  if info == nil then
    return
  end
  log_info(host, port, cpe, vendor, product, info)
  local v, vu = correct_version(info)
  local vctx = {
    os = ctx.os,
    backport = ctx.backport,
    version_source = version_source,
  }
  local tmp_vulns = service_vulns(host, port, cpe, vendor, product, v, vu,
    info, vctx)
  add_lines(vulns_out, logged, vendor, product, v, vu, tmp_vulns)
end


--- Return the vulns of a port's matches; ctx has OS and distro data.
local function analysis(host, port, matches, ctx)
  local vulns_out = {}
  local logged = {}
  for origin, data in pairs(matches['data']) do
    for cpe, versions in pairs(data) do
      for version_str, _ in pairs(versions) do
        analyze_match(host, port, ctx, origin, cpe, version_str,
          vulns_out, logged)
      end
    end
  end
  return vulns_out
end

--- Return the vulns of a port's matches (see analysis).
M.analysis = analysis
--- Alias of analysis.
M.run = analysis

return M
