-- SPDX-License-Identifier: GPL-3.0-or-later
-- Probe list and dispatch for the cvescannerv2 NSE script.  (Layer L5)
--
-- Lists the version and OS probes of the SMB, IRC, NTP, UPnP and CUPS
-- services, selects them with the probes argument and runs them with a
-- per-key cache. No direct I/O: the probe modules do the network work.
-- Reads config.probes and config.probes_set; uses state.probe_cache and
-- state.host_os_probe_result as caches.

local nmap = require 'nmap'
local stdnse = require 'stdnse'
local config = require 'cvescannerv2.config'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local version = require 'cvescannerv2.version'
local smb = require 'cvescannerv2.probes.smb'
local irc = require 'cvescannerv2.probes.irc'
local ntp = require 'cvescannerv2.probes.ntp'
local upnp = require 'cvescannerv2.probes.upnp'
local cups = require 'cvescannerv2.probes.cups'

local comm_ok = pcall(require, 'comm')

local M = {}

local fmt = util.fmt

-- Version and OS probes in scan order.
local SERVICE_PROBES = {
  smb.SMB_PROBE, irc.IRC_PROBE,
  ntp.NTP_PROBE,
  smb.SMB_OS_PROBE,
  upnp.UPNP_PROBE,
  cups.CUPS_PROBE,
}
M.SERVICE_PROBES = SERVICE_PROBES

--- Return whether the probe 'name' is selected by the probes argument.
-- The smb and smb_os probes also need smb.available.
local function probe_enabled(name)
  if (name == 'smb' or name == 'smb_os') and not smb.available then
    return false
  end
  if (name == 'ntp' or name == 'upnp')
      and not comm_ok then
    return false
  end
  if config.probes == 'none' then return false end
  return config.probes == 'all' or config.probes_set[name] == true
end
M.probe_enabled = probe_enabled

--- Return whether a probe applies to a port and a CPE product.
local function probe_applies(probe, port, product)
  if probe.products ~= nil and not probe.products[product] then
    return false
  end
  return (probe.services ~= nil and probe.services[port.service] == true)
    or (probe.ports ~= nil and probe.ports[port.number] == true)
end

--- Run a version probe with a per-key cache and return its result.
-- Errors and negative results are cached as false, so each key is
-- probed at most once.
local function run_version_probe(host, port, probe)
  if not probe_enabled(probe.name) then return nil end
  local cache = state.probe_cache[probe.name]
  if cache == nil then
    cache = {}
    state.probe_cache[probe.name] = cache
  end
  local key = fmt('%s:%s', host.ip, port.number)
  if probe.cache_key then key = probe.cache_key(host, port) end
  if cache[key] == nil then
    local ok, result = pcall(probe.run, host, port)
    if not ok then
      stdnse.verbose(2, fmt("%s probe error: %s", probe.name,
        tostring(result)))
      result = nil
    end
    cache[key] = result or false
  end
  return cache[key] or nil
end
M.run_version_probe = run_version_probe

--- Return the first OS family from an 'os' probe on an open TCP or UDP port.
-- Only the probes whose services or ports match an open port run.
local function first_os_probe(host)
  for port in nmap.get_ports(host, nil, 'tcp', 'open') do
    for _, probe in ipairs(SERVICE_PROBES) do
      if probe.kind == 'os' and probe_enabled(probe.name)
          and probe_applies(probe, port, nil) then
        local ok, result = pcall(probe.run, host)
        if ok and type(result) == 'table' and result.family then
          return result.family, probe.name
        end
      end
    end
  end
  return nil, nil
end

--- Return the OS family found by the 'os' probes of a host.
-- Return {family, source} or nil. The round is cached per IP, false marks
-- a negative result, and a Nmap mutex serializes it when available.
local function host_probe_os(host)
  if state.host_os_probe_result[host.ip] == nil then
    local lock = nil
    if type(nmap.mutex) == 'function' then lock = nmap.mutex(host.ip) end
    if lock then lock('lock') end
    if state.host_os_probe_result[host.ip] == nil then
      local ok, family, name = pcall(first_os_probe, host)
      if ok and family ~= nil then
        state.host_os_probe_result[host.ip] = {
          family = family,
          source = 'probe:' .. name,
        }
      else
        state.host_os_probe_result[host.ip] = false
      end
    end
    if lock then lock('done') end
  end
  return state.host_os_probe_result[host.ip] or nil
end
M.host_probe_os = host_probe_os

--- Return the first applicable version probe and its result.
-- Without a product (no Nmap CPE) only the 'no_cpe' probes of the service
-- apply. Skip the probes when the Nmap version is already precise.
local function version_probe_result(host, port, product, nmap_version)
  if version.is_precise_nmap_version(nmap_version) then return nil end
  for _, probe in ipairs(SERVICE_PROBES) do
    local applies
    if product ~= nil then
      applies = probe_applies(probe, port, product)
    else
      applies = probe.no_cpe == true and probe.services ~= nil
        and probe.services[port.service] == true
    end
    if probe.kind == 'version' and applies then
      local result = run_version_probe(host, port, probe)
      if result then return probe, result end
    end
  end
  return nil
end
M.version_probe_result = version_probe_result

return M
