-- SPDX-License-Identifier: GPL-3.0-or-later
-- JSON report for the cvescannerv2 NSE script.  (Layer L2)
--
-- Builds the schema 2 document from the result of each service and writes
-- it as one JSON Lines record. Keeps the hosts in state.json_report (an
-- array) and their index in state.json_hosts. Reads state.run_timestamp.
-- No network or SQL access.

local M = {}


local json = require 'json'

local state = require 'cvescannerv2.state'


local NULL = json.NULL


-- Mark a list as a JSON array, so an empty list is written as [].
local function array(list)
  if json.make_array then return json.make_array(list) end
  return list
end


-- Return a copy of a list as a JSON array.
local function list_copy(list)
  local out = {}
  for i, value in ipairs(list or {}) do out[i] = value end
  return array(out)
end


-- Return value, or the JSON null when value is nil.
local function nullable(value)
  if value == nil then return NULL end
  return value
end


-- Return the host entry of ip, creating it when it does not exist.
local function ensure_host(ip)
  state.json_report = state.json_report or {}
  state.json_hosts = state.json_hosts or {}
  if state.json_hosts[ip] == nil then
    local entry = { ip = ip, ports = array({}) }
    state.json_hosts[ip] = entry
    table.insert(state.json_report, entry)
  end
  return state.json_hosts[ip]
end
M.ensure_host = ensure_host


-- Return the port entry of a host, creating it when it does not exist.
local function ensure_port(host, port)
  for _, entry in ipairs(host.ports) do
    if entry.port == port.number and entry.protocol == port.protocol then
      return entry
    end
  end
  local entry = {
    port = port.number,
    protocol = port.protocol,
    service = nullable(port.service),
    products = array({}),
  }
  table.insert(host.ports, entry)
  return entry
end


-- Return the exploit references of a CVE as JSON objects.
local function exploit_list(exploits)
  local out = {}
  for _, exploit in ipairs(exploits or {}) do
    out[#out + 1] = {
      id = nullable(exploit.id),
      name = nullable(exploit.name),
      url = nullable(exploit.url),
    }
  end
  return array(out)
end


-- Return one CVE of a product as a JSON object. Includes every CVE.
local function cve_object(cve)
  local cvss = cve.cvss or {}
  return {
    id = cve.id,
    cvss = {
      v4 = nullable(cvss.v4),
      v3 = nullable(cvss.v3),
      v2 = nullable(cvss.v2),
    },
    confidence = cve.confidence,
    reasons = list_copy(cve.reasons),
    exploitdb = exploit_list(cve.exploitdb),
    metasploit = list_copy(cve.metasploit),
  }
end


-- Return the product entry of one service result.
local function product_object(result, cached)
  local os_ctx = result.os_context or {}
  local counts = result.counts
  local cves = {}
  for _, cve in ipairs(result.cves) do
    cves[#cves + 1] = cve_object(cve)
  end
  return {
    cpe = result.cpe,
    vendor = result.vendor,
    product = result.product,
    version = result.version,
    update = nullable(result.update),
    version_source = nullable(result.version_source),
    os_context = {
      family = nullable(os_ctx.family),
      distro = nullable(os_ctx.distro),
      source = nullable(os_ctx.source),
    },
    warnings = list_copy(result.warnings),
    cached = cached == true,
    counts = {
      total = counts.total,
      high = counts.high,
      medium = counts.medium,
      low = counts.low,
    },
    cves = array(cves),
  }
end


-- Add the result of one service to the report of its host and port.
-- port is the Nmap port table; cached is true for a reused result.
local function add_service(ip, port, result, cached)
  local host = ensure_host(ip)
  local port_entry = ensure_port(host, port)
  table.insert(port_entry.products, product_object(result, cached))
end
M.add_service = add_service


-- Append the JSON Lines record of the run to the file at path.
local function write(path, doc_ctx)
  local doc = {
    schema_version = 2,
    scanner = { name = 'cvescannerv2', version = doc_ctx.version },
    timestamp = state.run_timestamp,
    args = { minconf = doc_ctx.minconf, maxcve = doc_ctx.maxcve },
    hosts = array(state.json_report or {}),
  }
  local json_out = io.open(path, 'a')
  json_out:write(json.generate(doc))
  json_out:write("\n")
  json_out:close()
end
M.write = write


return M
