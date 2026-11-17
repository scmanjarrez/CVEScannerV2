-- SPDX-License-Identifier: GPL-3.0-or-later
-- CUPS version probe for the cvescannerv2 NSE script.  (Layer L4)
--
-- Reads the title of the GET / page served by CUPS (IPP) to get the exact
-- CUPS version. A 403 page (access denied) also carries the title.
-- E/S: red (http.get a GET / del host). Lee config.options_for_target();
-- no lee ni escribe state.

local http = require 'http'
local stdnse = require 'stdnse'
local config = require 'cvescannerv2.config'
local util = require 'cvescannerv2.util'

local M = {}

local fmt = util.fmt

--- Return the CUPS CPE and version from the title of the GET / page.
-- A 403 page (access denied) also carries the title, so 403 is accepted.
-- Return nil for other products, other status codes and failed requests.
local function cups_probe(host, port)
  local ok, response = pcall(http.get, host, port, '/',
    config.options_for_target())
  if not ok or type(response) ~= 'table' then
    stdnse.verbose(2, fmt("cups probe failed on %s:%d", host.ip,
      port.number))
    return nil
  end
  local status = tonumber(response.status)
  if status ~= 200 and status ~= 403 then return nil end
  if type(response.body) ~= 'string' then return nil end
  local title = response.body:match(
    '<[tT][iI][tT][lL][eE][^>]*>(.-)</[tT][iI][tT][lL][eE]%s*>')
  local version = title and title:match('CUPS v?(%d+%.%d+[%.%d]*)')
  if version == nil then return nil end
  return { cpe = 'cpe:/a:apple:cups', version = version }
end

--- The 'version' probe of the CUPS service, as used by the scanner.
M.CUPS_PROBE = {
  name = 'cups',
  kind = 'version',
  products = { cups = true },
  services = { ipp = true },
  run = cups_probe,
}

return M
