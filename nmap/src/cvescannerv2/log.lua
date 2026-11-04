-- SPDX-License-Identifier: GPL-3.0-or-later
-- Log file helpers for the cvescannerv2 NSE script.

local M = {}


local stdnse = require 'stdnse'

local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local correct_version = require('cvescannerv2.version').correct_version
local fmt = util.fmt


-- Open the log file in append mode and keep it in the shared state.
local function open(path)
  state.logger = io.open(path, 'a')
end
M.open = open


-- Write a final newline and close the log file kept in the shared state.
local function close()
  state.logger:write("\n")
  state.logger:close()
end
M.close = close


-- Write the run timestamp to the log and print the run details.
local function timestamp(script_version)
  state.logger:write(fmt("## %s\n", state.time))
  stdnse.verbose(1, fmt("Timestamp: %s", state.time))
  stdnse.verbose(1, fmt("CVE data source: %s", "nvd.nist.gov"))
  stdnse.verbose(1, fmt("Script version: %s", script_version))
end
M.timestamp = timestamp


local function log(msg, ...)
  state.logger:write(fmt(msg .. "\n", ...))
end
M.log = log


local function log_separator()
  log(string.rep("-", 49))
end
M.log_separator = log_separator


local function log_info(host, port, cpe, vendor, product, info)
  local _ip = host.ip
  local _port = port.number
  local _proto = port.protocol
  local _serv = port.service
  local _prod = product
  local _ver, _vupd = correct_version(info)
  log("[*] host: %s", _ip)
  log("[*] port: %s", _port)
  log("[+] protocol: %s", _proto)
  log("[+] service: %s", _serv)
  log("[+] cpe: %s", cpe)
  log("[+] vendor: %s", vendor)
  log("[+] product: %s", _prod)
  log("[+] version: %s", _ver)
  log("[+] vupdate: %s", _vupd)
end
M.log_info = log_info


return M
