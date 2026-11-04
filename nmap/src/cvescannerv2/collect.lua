-- SPDX-License-Identifier: GPL-3.0-or-later
-- Match collection for one port of the cvescannerv2 NSE script.  (Layer L6)
--
-- Gathers the matches of a port from the Nmap version, the version probes,
-- the banner and the HTTP fingerprint engine. The analysis of the matches
-- stays in the entrypoint. No direct I/O: the probes and HTTP requests live
-- in 'probes' and 'httpscan'. Reads 'state.product_cpe'.

local cpe = require 'cvescannerv2.cpe'
local fingerprint = require 'cvescannerv2.fingerprint'
local httpscan = require 'cvescannerv2.httpscan'
local match_mod = require 'cvescannerv2.matches'
local probes = require 'cvescannerv2.probes.init'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'

local M = {}

local empty = util.empty
local add_cpe_version = match_mod.add_cpe_version
local add_cpe_aliases = match_mod.add_cpe_aliases
local split_cpe = cpe.split_cpe
local match_banner = fingerprint.match_banner
local http_match = httpscan.http_match
local use_http_engine = httpscan.use_http_engine
local version_probe_result = probes.version_probe_result


--- Return an empty matches table with one bucket per origin.
function M.new_matches()
  return {
    ['data'] = {
      ['nmap'] = {}, ['http'] = {}, ['smb'] = {}, ['irc'] = {},
      ['ntp'] = {}, ['upnp'] = {}
    },
    ['size'] = 0
  }
end


--- Add the version found by a version probe, or the CPE of a port.
-- Without a Nmap CPE, only the 'no_cpe' version probes can add a match.
-- A product listed in the product CPE table uses the table CPE instead
-- of the Nmap one, with the first numeric token of the Nmap version.
local function add_nmap_matches(host, port, matches)
  local cpe = port.version.cpe and port.version.cpe[1] or nil
  local detected_version = port.version.version
  local override = state.product_cpe[port.version.product]
  if override ~= nil then
    cpe = override
    detected_version = (detected_version or ''):match('%d[%d%.]*')
  end
  if empty(detected_version) then detected_version = '*' end
  local product = nil
  if cpe ~= nil then
    local _, _, _, _, name = split_cpe(cpe)
    product = name
  end
  local probe, result = version_probe_result(host, port, product,
    detected_version)
  if probe then
    local version = result.version .. (result.update or '')
    matches.data[probe.name] = matches.data[probe.name] or {}
    add_cpe_version(result.cpe, version, matches, probe.name)
    return
  end
  if cpe == nil then return end
  add_cpe_version(cpe, detected_version, matches, 'nmap')
  add_cpe_aliases(cpe, detected_version, matches, 'nmap')
end
M.add_nmap_matches = add_nmap_matches


--- Return the matches recorded for one port.
-- The Nmap version comes first, then the banner and the HTTP fingerprint
-- engine.
function M.port(host, port)
  local matches = M.new_matches()
  local triggered = {}
  if port.version ~= nil then
    add_nmap_matches(host, port, matches)
  end
  match_banner(port, matches, triggered)
  if use_http_engine(host, port) then
    http_match(host, port, matches, triggered)
  end
  return matches
end


return M
