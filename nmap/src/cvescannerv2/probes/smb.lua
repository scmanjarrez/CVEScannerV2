-- SPDX-License-Identifier: GPL-3.0-or-later
-- SMB version and OS probes for the cvescannerv2 NSE script.

-- Reads the SMB service with the Nmap smb library, once per host. The Samba
-- version and the OS family found here feed the version and OS detection.

local stdnse = require 'stdnse'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'

local smb_ok, smb = pcall(require, 'smb')

local M = {}

M.available = smb_ok

local fmt = util.fmt

local SMB_PORTS = { [139] = true, [445] = true }
local SMB_SERVICES = { ['microsoft-ds'] = true, ['netbios-ssn'] = true }

--- Return the SMB OS info of a host, calling smb.get_os at most once.
-- Return nil when the probe fails. Failures are cached as false.
local function smb_get_os(host)
  local cached = state.smb_info[host.ip]
  if cached == nil then
    local ok, status, info = pcall(smb.get_os, host)
    if not ok then
      stdnse.verbose(2, fmt("smb probe failed: %s", tostring(status)))
    elseif not status then
      stdnse.verbose(2, fmt("smb probe failed: %s", tostring(info)))
    end
    cached = ok and status and info or false
    state.smb_info[host.ip] = cached
  end
  return cached or nil
end

--- Return the Samba CPE and exact version reported by the SMB service.
-- Return nil when the host does not run Samba or the probe fails.
local function smb_probe(host)
  local info = smb_get_os(host)
  if type(info) == 'table' and type(info.lanmanager) == 'string' then
    local version = info.lanmanager:match('^Samba%s+([%d%.]+[%w%.]*)')
    if version then
      return { cpe = 'cpe:/a:samba:samba', version = version }
    end
  end
  return nil
end

-- Version probes. A probe fires when its product matches the CPE product
-- and either the port service or the port number is listed.
local SMB_PROBE = {
  name = 'smb',
  kind = 'version',
  products = { samba = true },
  services = SMB_SERVICES,
  ports = SMB_PORTS,
  -- One SMB probe per host, shared by all of its SMB ports.
  cache_key = function(host) return host.ip end,
  run = smb_probe,
}

-- OS probe: the SMB service reports the OS family of the host. Samba is not
-- mapped to a family: 'unix' never equals the 'linux' family of
-- evaluate_platform, which would add false platform_mismatch reasons.
local function smb_os_probe(host)
  local info = smb_get_os(host)
  if type(info) ~= 'table' then return nil end
  -- Samba on Linux reports 'Windows 6.1' in the os field: skip it.
  if type(info.lanmanager) == 'string'
      and info.lanmanager:lower():find('^samba') then
    return nil
  end
  if type(info.os) == 'string' and info.os:find('^Windows') then
    return { family = 'windows' }
  end
  return nil
end

local SMB_OS_PROBE = {
  name = 'smb_os',
  kind = 'os',
  services = SMB_SERVICES,
  ports = SMB_PORTS,
  run = smb_os_probe,
}

M.SMB_PORTS = SMB_PORTS
M.SMB_SERVICES = SMB_SERVICES
M.smb_get_os = smb_get_os
M.smb_probe = smb_probe
M.SMB_PROBE = SMB_PROBE
M.smb_os_probe = smb_os_probe
M.SMB_OS_PROBE = SMB_OS_PROBE

return M
