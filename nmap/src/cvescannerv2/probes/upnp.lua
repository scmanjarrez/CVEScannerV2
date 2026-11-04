-- SPDX-License-Identifier: GPL-3.0-or-later
-- UPnP version probe for the cvescannerv2 NSE script.

-- Sends an SSDP M-SEARCH to the UPnP port and reads the SERVER header to
-- get the miniupnpd version.

local stdnse = require 'stdnse'
local util = require 'cvescannerv2.util'

local comm_ok, comm = pcall(require, 'comm')

local M = {}

local fmt = util.fmt

--- Return the value of the SERVER header of an SSDP reply, or nil.
local function upnp_server_header(response)
  for line in response:gmatch('[^\r\n]+') do
    local value = line:match('^[Ss][Ee][Rr][Vv][Ee][Rr]:%s*(.-)%s*$')
    if value then return value end
  end
  return nil
end
M.upnp_server_header = upnp_server_header

--- Return the miniupnpd CPE and version from the SSDP SERVER header.
-- Return nil for other UPnP servers and for failed requests.
local function upnp_probe(host, port)
  -- SSDP M-SEARCH sent unicast to the UPnP port of the host.
  local msearch = 'M-SEARCH * HTTP/1.1\r\n'
    .. 'HOST: 239.255.255.250:1900\r\n'
    .. 'MAN: "ssdp:discover"\r\n'
    .. 'MX: 1\r\n'
    .. 'ST: upnp:rootdevice\r\n\r\n'
  local ok, status, response = pcall(comm.exchange, host, port,
    msearch, { proto = 'udp', timeout = 3000 })
  if not ok or not status or type(response) ~= 'string' then
    stdnse.verbose(2, fmt("upnp probe failed on %s:%d", host.ip,
      port.number))
    return nil
  end
  local server = upnp_server_header(response)
  if server == nil then return nil end
  local version = server:match(
    '[Mm]ini[Uu][Pp][Nn][Pp][Dd]/(%d+%.%d+[%.%d]*)')
  if version == nil then return nil end
  return { cpe = 'cpe:/a:miniupnp_project:miniupnpd', version = version }
end
M.upnp_probe = upnp_probe

--- The 'version' probe of the UPnP service, as used by the scanner.
M.UPNP_PROBE = {
  name = 'upnp',
  kind = 'version',
  services = { upnp = true },
  -- Nmap gives no CPE for UPnP: the probe also runs on the bare service.
  no_cpe = true,
  run = upnp_probe,
}

return M
