-- SPDX-License-Identifier: GPL-3.0-or-later
-- JSON report helpers for the cvescannerv2 NSE script.
-- The report is kept in state.json_out and written by postaction.

local M = {}


local json = require 'json'

local state = require 'cvescannerv2.state'


-- Create the host entry of the report if it does not exist yet.
local function ensure_host(ip)
  if state.json_out[ip] == nil then
    state.json_out[ip] = {
      ['timestamp'] = state.time,
      ['ports'] = {}
    }
  end
end
M.ensure_host = ensure_host


-- Create the port entry of a host if it does not exist yet.
local function ensure_port(ip, port_proto)
  if state.json_out[ip]['ports'][port_proto] == nil then
    state.json_out[ip]['ports'][port_proto] = { ['services'] = {} }
  end
end
M.ensure_port = ensure_port


-- Append a service entry to the services of a port.
local function add_service(ip, port_proto, entry)
  table.insert(state.json_out[ip]['ports'][port_proto]['services'], entry)
end
M.add_service = add_service


-- Return the last service recorded for a port.
local function last_service(ip, port_proto)
  local services = state.json_out[ip]['ports'][port_proto]['services']
  return services[#services]
end
M.last_service = last_service


-- Set the CVE record of the last service of a port.
local function set_cve(ip, port_proto, vuln, record)
  last_service(ip, port_proto)['vulnerabilities']['cves'][vuln] = record
end
M.set_cve = set_cve


-- Set the total of vulnerabilities of the last service of a port.
local function set_total(ip, port_proto, nvulns)
  last_service(ip, port_proto)['vulnerabilities']['total'] = nvulns
end
M.set_total = set_total


-- Append the JSON report to the file at path.
local function write(path)
  local json_out = io.open(path, 'a')
  json_out:write(json.generate(state.json_out))
  json_out:write("\n")
  json_out:close()
end
M.write = write


return M
