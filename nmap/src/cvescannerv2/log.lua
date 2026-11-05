-- SPDX-License-Identifier: GPL-3.0-or-later
-- Log file helpers for the cvescannerv2 NSE script.  (Layer L2)
--
-- Appends to the log file opened in state.log_file (io.open, append mode)
-- and prints run details through stdnse. Reads state.run_timestamp and formats
-- versions with cvescannerv2.version. Does no network I/O and does not
-- read config.

local M = {}


local stdnse = require 'stdnse'

local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local display_version = require('cvescannerv2.version').display_version
local fmt = util.fmt


--- Open the log file in append mode and keep it in the shared state.
local function open(path)
  state.log_file = io.open(path, 'a')
end
M.open = open


--- Write a final newline and close the log file kept in the shared state.
local function close()
  state.log_file:write("\n")
  state.log_file:close()
end
M.close = close


--- Write the run timestamp to the log and print the run details.
local function log_run_header(script_version)
  state.log_file:write(fmt("## %s\n", state.run_timestamp))
  stdnse.verbose(1, fmt("Timestamp: %s", state.run_timestamp))
  stdnse.verbose(1, fmt("CVE data source: %s", "nvd.nist.gov"))
  stdnse.verbose(1, fmt("Script version: %s", script_version))
end
M.log_run_header = log_run_header


--- Write a formatted line to the log file.
local function write(msg, ...)
  state.log_file:write(fmt(msg .. "\n", ...))
end
M.write = write


--- Write a dashed separator line to the log file.
local function log_separator()
  write(string.rep("-", 49))
end
M.log_separator = log_separator


--- Write the host, port and product details of one match to the log.
local function log_service(host, port, cpe, vendor, product, info)
  local _ip = host.ip
  local _port = port.number
  local _proto = port.protocol
  local _serv = port.service
  local _prod = product
  local _ver, _vupd = display_version(info)
  write("[*] host: %s", _ip)
  write("[*] port: %s", _port)
  write("[+] protocol: %s", _proto)
  write("[+] service: %s", _serv)
  write("[+] cpe: %s", cpe)
  write("[+] vendor: %s", vendor)
  write("[+] product: %s", _prod)
  write("[+] version: %s", _ver)
  write("[+] vupdate: %s", _vupd)
end
M.log_service = log_service


return M
