-- SPDX-License-Identifier: GPL-3.0-or-later
-- HTTP fingerprint engine for the cvescannerv2 NSE script.  (Layer L4)
--
-- Reads HTTP responses from a port (network I/O through the Nmap http
-- library, paced by nmap.timing_level) and feeds them to the fingerprint
-- and version matchers: targeted probes and the optional catalogue sweep.
-- Reads state.catalog and config (sweep, maxredirect, options_for_target).

local http = require 'http'
local nmap = require 'nmap'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local config = require 'cvescannerv2.config'
local fingerprint = require 'cvescannerv2.fingerprint_match'
local match_table = require 'cvescannerv2.match_table'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local version = require 'cvescannerv2.version'

local M = {}

local fmt = util.fmt
local add_cpe_version = match_table.add_cpe_version
local cpe_has_precise_version = match_table.cpe_has_precise_version
local prune_series_versions = match_table.prune_series_versions
local is_precise_version = version.is_precise_version
local match_subjects = fingerprint.match_subjects
local extract_probe_version = fingerprint.extract_probe_version
local response_subjects = fingerprint.response_subjects


--- Return true when the response status is 2xx or 3xx.
local function response_is_usable(response)
  local status = tonumber(response.status)
  return status ~= nil and status >= 200 and status < 400
end


--- Fetch the paths of triggered probes and record their versions.
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
            local ver = extract_probe_version(probe, body)
            if ver then
              add_cpe_version(probe.alias, ver, matches, 'http')
              if is_precise_version(ver) then
                prune_series_versions(matches, probe.alias, ver)
              end
            end
          end
        end
      end
    end
  end
end

--- Request every catalogue path in paced batches and match replies.
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

--- Run the catalogue sweep and targeted probes when catalogue is loaded.
local function match_http_fingerprints(host, port, matches, triggered)
  if state.catalog_loaded then
    -- The catalogue sweep only runs with sweep=1 because it is slow.
    if config.sweep then
      sweep_catalog(host, port, matches, triggered)
    end
    run_targeted_probes(host, port, matches, triggered)
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


M.response_is_usable = response_is_usable
M.run_targeted_probes = run_targeted_probes
M.sweep_catalog = sweep_catalog
M.match_http_fingerprints = match_http_fingerprints
M.use_http_engine = use_http_engine

return M
