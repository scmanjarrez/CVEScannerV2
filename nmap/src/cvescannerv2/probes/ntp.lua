-- SPDX-License-Identifier: GPL-3.0-or-later
-- NTP version probe for the cvescannerv2 NSE script.

-- Reads the ntpd readvar reply (mode 6) to get the exact ntpd version and
-- the patch level. The reply is cached per host and port in the state.

local stdnse = require 'stdnse'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'

local comm_ok, comm = pcall(require, 'comm')

local M = {}

local fmt = util.fmt

--- Return the version and system fields of a mode 6 readvar reply.
-- The payload follows the 12-byte header. Return nil without a version.
local function ntp_parse_readvar(response)
  local payload = response:sub(13)
  local version = payload:match('version="([^"]*)"')
  if version == nil then return nil end
  return { version = version, system = payload:match('system="([^"]*)"') }
end
M.ntp_parse_readvar = ntp_parse_readvar

--- Return the readvar fields of an NTP service, calling it at most once.
-- Return nil when the request fails. Failures are cached as false.
local function ntp_get_info(host, port)
  local key = fmt('%s:%d', host.ip, port.number)
  local cached = state.ntp_info[key]
  if cached == nil then
    -- Mode 6 readvar request, the same packet as the ntp-info script.
    local readvar = '\x16\x02\x00\x01' .. string.rep('\0', 8)
    local ok, status, response = pcall(comm.exchange, host, port,
      readvar, { proto = 'udp', timeout = 5000 })
    if ok and status and type(response) == 'string' then
      cached = ntp_parse_readvar(response) or false
    else
      stdnse.verbose(2, fmt("ntp readvar failed on %s", key))
      cached = false
    end
    state.ntp_info[key] = cached
  end
  return cached or nil
end
M.ntp_get_info = ntp_get_info

--- Return the ntpd CPE, version and patch level from the readvar reply.
-- The patch level is the update, as in the NVD rows. Return nil for other
-- daemons such as ntpsec or chrony.
local function ntp_probe(host, port)
  local info = ntp_get_info(host, port)
  if info == nil then return nil end
  local version, rest = info.version:match('^ntpd (%d+%.%d+%.%d+)(.*)$')
  if version == nil then return nil end
  return {
    cpe = 'cpe:/a:ntp:ntp',
    version = version,
    update = rest:match('^(p%d+)'),
  }
end
M.ntp_probe = ntp_probe

--- The 'version' probe of the NTP service, as used by the scanner.
M.NTP_PROBE = {
  name = 'ntp',
  kind = 'version',
  products = { ntp = true },
  services = { ntp = true },
  -- Nmap gives no CPE for NTP: the probe also runs on the bare service.
  no_cpe = true,
  run = ntp_probe,
}

return M
