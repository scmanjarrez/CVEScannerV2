-- SPDX-License-Identifier: GPL-3.0-or-later
-- HTTP fingerprint engine for the cvescannerv2 NSE script.

-- Reads HTTP responses from a port and feeds the headers and bodies to the
-- fingerprint and version matchers. The catalogue sweep and the targeted
-- probes run when the catalogue is loaded. The legacy path runs otherwise.

local http = require 'http'
local nmap = require 'nmap'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local config = require 'cvescannerv2.config'
local fingerprint = require 'cvescannerv2.fingerprint'
local match_mod = require 'cvescannerv2.matches'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local ver_mod = require 'cvescannerv2.version'

local M = {}

local fmt = util.fmt
local add_cpe_version = match_mod.add_cpe_version
local cpe_has_precise_version = match_mod.cpe_has_precise_version
local prune_series_versions = match_mod.prune_series_versions
local is_precise_version = ver_mod.is_precise_version
local match_subjects = fingerprint.match_subjects
local probe_version = fingerprint.probe_version
local response_subjects = fingerprint.response_subjects


local function find_version(cpe, text, regex, matches)
  local idx = 0
  local sidx = 0
  local version
  while true do
    sidx, idx, version = text:find(regex, idx + 1)
    if version then
      if version == '' then
        version = '*'
      end
      local msg = add_cpe_version(cpe, version, matches, 'http')
      if msg then
        stdnse.verbose(2, "http find_version matched text: " ..
          text:sub(sidx, idx) ..
          " | version: " .. version)
      end
    end
    if idx == nil then break end
  end
end


local function regex_match(text, location, matches)
  for _, software in pairs(state.regex[location]) do
    if type(software.regex) == 'table' then
      for _, regex in pairs(software.regex) do
        find_version(software.cpe, text, regex, matches)
      end
    else
      find_version(software.cpe, text, software.regex, matches)
    end
  end
end

local HTTP_MAX_FAILURES = 5

local function legacy_get(host, port, file)
  return http.get(host, port, file,
    {
      redirect_ok = config.maxredirect,
      timeout = 10000,
      max_body_size = 131072,
      truncated_ok = true,
      bypass_cache = true,
      no_cache = true,
      no_cache_body = true
    }
  )
end

local function legacy_scan_response(resp, matches)
  if resp.rawheader and #resp.rawheader > 0 then
    for _, header in pairs(resp.rawheader) do
      regex_match(header, 'header', matches)
    end
  end
  local rawbody = resp.rawbody or ''
  if rawbody ~= '' then
    regex_match(rawbody, 'body', matches)
  end
end

-- Record the library versions declared in one JavaScript comment.
local function record_comment_versions(lib_comm, libs)
  local idy = 0
  local comm_lib = nil
  local comm_ver = nil
  while true do
    _, idy, comm_lib, comm_ver = lib_comm:find(
      state.regex['external']['version_regex'],
      idy + 1)
    if comm_lib and comm_ver then
      if comm_lib:lower() ~= 'version' then
        stdnse.verbose(2,
          "Matched version in js " ..
          "comment: " .. comm_lib ..
          " ver: " .. comm_ver)
        libs[comm_lib] = comm_ver
        libs['size'] = libs['size'] + 1
      end
    end
    if idy == nil then break end
  end
end

-- Fetch the scripts referenced by the root page and collect their versions.
local function collect_js_libs(host, port, rawbody)
  local idx = 0
  local lib_path = nil
  local libs = { ['size'] = 0 }
  while true do
    _, idx, lib_path = rawbody:find(
      state.regex['external']['path_regex'], idx + 1)
    if lib_path and lib_path:sub(1, 1) == '/' then
      local lib_resp = legacy_get(host, port, lib_path)
      if lib_resp.status and lib_resp.rawbody ~= nil then
        local _, _, lib_comm = lib_resp.rawbody:find(
          state.regex['external']['comment_regex'])
        if lib_comm then
          stdnse.verbose(3, "Comment: " .. lib_comm)
          record_comment_versions(lib_comm, libs)
        end
      end
    end
    if idx == nil then break end
  end
  return libs
end

local function match_js_libs(libs, matches)
  if libs['size'] > 0 then
    for name, data in pairs(state.regex['body']) do
      for k, v in pairs(libs) do
        if k ~= 'size' then
          local k_stripped = (k:gsub('%.js$', '')):lower()
          if (name:lower()):find(k_stripped, 1, true) then
            add_cpe_version(data['cpe'], v, matches, 'http')
          end
        end
      end
    end
  end
end

local function http_match_legacy(host, port, matches)
  local failures = 0
  for _, path in pairs(state.path['path']) do
    for _, ext in pairs(state.path['extension']) do
      local file = "/" .. path .. ext
      if (path == '' and ext == '') or path ~= '' then
        local resp = legacy_get(host, port, file)
        if not resp.status then
          failures = failures + 1
          stdnse.verbose(2,
            fmt("Error processing request http://%s:%s%s => %s",
              host.ip, port.number, file, resp['status-line']))
          if failures >= HTTP_MAX_FAILURES then
            stdnse.verbose(2, fmt("Stopping http checks on %s:%s "
              .. "after %d failures", host.ip, port.number, failures))
            return
          end
        else
          failures = 0
          legacy_scan_response(resp, matches)
        end
        if path == '' and ext == '' and resp.status then
          local libs = collect_js_libs(host, port, resp.rawbody or '')
          match_js_libs(libs, matches)
        end
      end
    end
  end
end

local function response_is_usable(response)
  local status = tonumber(response.status)
  return status ~= nil and status >= 200 and status < 400
end


local function run_targeted_probes(host, port, matches, triggered)
  local probes_used = 0
  for _, probe in ipairs(state.catalog.probes) do
    if triggered[probe.alias]
        and not cpe_has_precise_version(matches, probe.alias)
        and probes_used < 3 then
      probes_used = probes_used + 1
      local paths_used = 0
      for _, path in ipairs(probe.paths) do
        if paths_used >= 3
            or cpe_has_precise_version(matches, probe.alias) then
          break
        end
        paths_used = paths_used + 1
        local response = http.get(host, port, path,
          config.options_for_target())
        if type(response) == 'table' and response_is_usable(response) then
          local body = response.body
          if type(body) == 'string' then
            local version = probe_version(probe, body)
            if version then
              add_cpe_version(probe.alias, version, matches, 'http')
              if is_precise_version(version) then
                prune_series_versions(matches, probe.alias, version)
              end
            end
          end
        end
      end
    end
  end
end

local function sweep_catalog(host, port, matches, triggered)
  local pace = {
    [0] = { 5, 2.0 },
    [1] = { 10, 1.0 },
    [2] = { 25, 0.5 },
    [3] = { 100, 0.1 },
    [4] = { 250, 0 },
    [5] = { 250, 0 }
  }
  local setting = pace[nmap.timing_level()] or pace[3]
  local batch_size = setting[1]
  local delay = setting[2]
  local paths = state.catalog.paths
  local start = 1
  while start <= #paths do
    local requests = nil
    local finish = math.min(start + batch_size - 1, #paths)
    for idx = start, finish do
      requests = http.pipeline_add(paths[idx], config.options_for_target(),
        requests)
    end
    local responses = http.pipeline_go(host, port, requests)
    local answered = false
    if type(responses) == 'table' then
      for idx, response in ipairs(responses) do
        if type(response) == 'table' and response.status ~= nil then
          answered = true
        end
        if type(response) == 'table' and config.maxredirect > 0 then
          local status = tonumber(response.status)
          if status == 301 or status == 302 or status == 303
              or status == 307 or status == 308 then
            -- Pipelines do not follow redirects. Reissue this path through
            -- get() to apply Nmap's redirect checks and maxredirect limit.
            response = http.get(host, port, paths[start + idx - 1],
              config.options_for_target())
          end
        end
        if type(response) == 'table' and response_is_usable(response) then
          match_subjects(response_subjects(response), matches,
            'http', triggered)
        elseif type(response) == 'table'
            and tonumber(response.status) == 403 then
          match_subjects(response_subjects(response), matches,
            'http', triggered, true)
        end
      end
    end
    if not answered then
      stdnse.verbose(2, fmt("No http answers on %s:%s; stopping sweep",
        host.ip, port.number))
      break
    end
    start = finish + 1
    if delay > 0 and start <= #paths then stdnse.sleep(delay) end
  end
end

local function http_match(host, port, matches, triggered)
  if state.catalog_loaded then
    -- The catalogue sweep is opt-in (sweep=1) because it is slow.
    if config.sweep == '1' then
      sweep_catalog(host, port, matches, triggered)
    end
    run_targeted_probes(host, port, matches, triggered)
  elseif state.legacy_catalog then
    http_match_legacy(host, port, matches)
  end
end


-- Services that Nmap identifies but that do not speak HTTP, even when
-- wrapped in TLS. The http engine must skip them.
local NON_HTTP_SERVICES = {
  ['ms-wbt-server'] = true, ['ms-sql-s'] = true, ['mysql'] = true,
  ['postgresql'] = true, ['ssh'] = true, ['ftp'] = true, ['ftps'] = true,
  ['smtp'] = true, ['smtps'] = true, ['imap'] = true, ['imaps'] = true,
  ['pop3'] = true, ['pop3s'] = true, ['ldap'] = true, ['ldapssl'] = true,
  ['ldaps'] = true, ['vnc'] = true, ['microsoft-ds'] = true,
  ['netbios-ssn'] = true, ['msrpc'] = true, ['telnet'] = true,
  ['domain'] = true, ['ntp'] = true, ['snmp'] = true,
}

--- Return true when the http fingerprint engine applies to a port.
-- Plain HTTP and upnp always qualify. TLS ports qualify unless the
-- service is known to speak a non-HTTP protocol.
local function use_http_engine(host, port)
  if shortport.http(host, port) or port.service == 'upnp' then
    return true
  end
  return shortport.ssl(host, port) and not NON_HTTP_SERVICES[port.service]
end


M.find_version = find_version
M.regex_match = regex_match
M.HTTP_MAX_FAILURES = HTTP_MAX_FAILURES
M.http_match_legacy = http_match_legacy
M.response_is_usable = response_is_usable
M.run_targeted_probes = run_targeted_probes
M.sweep_catalog = sweep_catalog
M.http_match = http_match
M.NON_HTTP_SERVICES = NON_HTTP_SERVICES
M.use_http_engine = use_http_engine

return M
