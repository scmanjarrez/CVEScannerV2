-- SPDX-License-Identifier: GPL-3.0-or-later

-- cvescannerv2 - NSE script.

-- Copyright (C) 2021-2023 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
-- Universidad Carlos III de Madrid (UC3M).

-- Copyright (C) 2026 Sergio Chica Manjarrez @ csic.es.
-- Consejo Superior de Investigaciones Científicas (CSIC).

-- This file is part of CVEScannerV2.

-- CVEScannerV2 is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- CVEScannerV2 is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

description = [[
Search for probable vulnerabilities based on services discovered in open ports.
CVEs information gathered from nvd.nist.gov.
]]
--- Prerequisite: data/cve.db. Generate it with db-manager or obtain it from
-- https://github.com/scmanjarrez/CVEScannerV2DB
--
--- Run: Execute CVEscannerV2
-- @usage nmap -sV --script cvescannerv2 <target-ip>
-- @usage nmap -sV --script cvescannerv2 --script-args log=logfile.log,json=logfile.json <target-ip>
--
-- @output
-- PORT      STATE SERVICE       VERSION
-- 3306/tcp  open  mysql         MySQL 5.5.55
-- | cvescannerv2:
-- |   source: nvd.nist.gov
-- |   product: mysql
-- |   version: 5.5.55
-- |   vupdate: *
-- |   cves: 5
-- |       CVE ID           CVSSv2   CVSSv3   ExploitDB   Metasploit
-- |       CVE-2021-3278    7.5      9.8      Yes         No
-- |       CVE-2014-3631    7.2      -        Yes         Yes
-- |       CVE-2019-13401   6.8      8.8      No          No
-- |       CVE-2019-13402   6.5      8.8      No          No
-- |_      CVE-2016-3976    5.0      7.5      Yes         Yes
--
--- Optional arguments
-- db: Modify the database file location. Default: data/cve.db
-- maxcve: Limit the number of CVEs printed on screen. Default: 10
-- http: Modify HTTP analysis behaviour. Default: 1 (enabled). Possible values: 0, 1
-- maxredirect: Limit the number of redirections. Default: 1
-- log: Modify the output .log file location. Default: cvescannerv2.log
-- json: Modify the output .json file location. Default: cvescannerv2.json
-- catalog: Use upstream fingerprints. Default: auto. Set to none to disable
-- HTTP fingerprinting.
-- catalog_url: Override the base URL for the upstream catalogue.
-- path: Legacy paths file. Default:
-- data/http-paths-vulnerscom.json
-- regex: Legacy regex file. Default:
-- data/http-regex-vulnerscom.json
-- aliases: Product aliases file. Default:
-- data/product-aliases.json
-- vendor_aliases: Vendor aliases file. Default:
-- data/vendor-aliases.json
-- service: Modify the search scope to specific service. Default: all
-- version: Modify the search scope to specific version. Default: all
-- smb: Probe SMB (ports 139/445) for the exact Samba version. Default: 1.
-- Possible values: 0, 1
-- minconf: Minimum confidence of the CVEs shown in the table and the log:
-- low, medium or high. Default: low. Invalid values use low. The JSON
-- report always keeps every CVE.
---

categories = { "safe" }
author = "Sergio Chica"
version = "4.0"

local http = require 'http'
http.USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0'
local json = require 'json'
local nmap = require 'nmap'
local datetime = require 'datetime'
local lfs = require 'lfs'
local shortport = require 'shortport'
local sql = require 'luasql.sqlite3'
local stdnse = require 'stdnse'
local smb_ok, smb = pcall(require, 'smb')

local db_arg = stdnse.get_script_args('db') or 'data/cve.db'
local maxcve_arg = tonumber(stdnse.get_script_args('maxcve')) or 10
local http_arg = stdnse.get_script_args('http') or '1'
local maxredirect_arg = math.max(
  0, tonumber(stdnse.get_script_args('maxredirect')) or 1)
local log_arg = stdnse.get_script_args('log') or 'cvescannerv2.log'
local json_arg = stdnse.get_script_args('json') or 'cvescannerv2.json'
-- local word_arg = stdnse.get_script_args('word') or nil
-- local ext_arg = stdnse.get_script_args('ext') or nil
local path_arg = stdnse.get_script_args('path')
    or 'data/http-paths-vulnerscom.json'
local regex_arg = stdnse.get_script_args('regex')
    or 'data/http-regex-vulnerscom.json'
local aliases_arg = stdnse.get_script_args('aliases')
    or 'data/product-aliases.json'
local vendor_aliases_arg = stdnse.get_script_args('vendor_aliases')
    or 'data/vendor-aliases.json'
local catalog_arg = (stdnse.get_script_args('catalog') or 'auto'):lower()
local catalog_url_arg = stdnse.get_script_args('catalog_url')
local service_arg = stdnse.get_script_args('service') or 'all'
local version_arg = stdnse.get_script_args('version') or 'all'
local smb_arg = stdnse.get_script_args('smb') or '1'
local minconf_raw = (stdnse.get_script_args('minconf') or 'low'):lower()
local minconf_valid = minconf_raw == 'low' or minconf_raw == 'medium'
    or minconf_raw == 'high'
local minconf_arg = minconf_valid and minconf_raw or 'low'


if not nmap.registry[SCRIPT_NAME] then
  nmap.registry[SCRIPT_NAME] = {
    conn = nil,
    cache = nil,
    env = nil,
    logger = nil,
    json_out = nil,
    path = nil,
    regex = nil,
    aliases = {},
    vendor_aliases = {},
    platform_families = {},
    host_os = {},
    catalog = { fingerprints = {}, paths = {}, probes = {} },
    catalog_loaded = false,
    legacy_catalog = false,
    smb = {},
    status = true,
    time = nil
  }
end


local registry = nmap.registry[SCRIPT_NAME]


local function empty(str)
  return str == nil or str == ''
end


local function exists(file)
  local f = io.open(file, 'r')
  return f ~= nil and f:close()
end


local function fmt(msg, ...)
  return msg:format(...)
end

local function sql_escape(value)
  return (tostring(value):gsub("'", "''"))
end

-- Implementation of named parameters from RiciLake@lua-users. A table value
-- becomes a comma-separated list of quoted literals, e.g. 'a', 'b'.
local function fmtn(msg, tab)
  return (msg:gsub(
    '($%b{})',
    function(nparam)
      -- nparam -> ${var} => nparam:sub(3, -2) -> var
      local value = tab[nparam:sub(3, -2)]
      if value == nil then return "nil" end
      if type(value) == 'table' then
        local literals = {}
        for i, item in ipairs(value) do
          literals[i] = "'" .. sql_escape(item) .. "'"
        end
        return table.concat(literals, ', ')
      end
      return sql_escape(value)
    end
  ))
end


local function timestamp()
  registry.logger:write(fmt("## %s\n", registry.time))
  stdnse.verbose(1, fmt("Timestamp: %s", registry.time))
  stdnse.verbose(1, fmt("CVE data source: %s", "nvd.nist.gov"))
  stdnse.verbose(1, fmt("Script version: %s", version))
end


local function correct_version(info)
  if not info.range then
    return info.ver, info.vup
  else
    return info.from .. " - " .. info.to, "*"
  end
end


local function log(msg, ...)
  registry.logger:write(fmt(msg .. "\n", ...))
end


local function log_separator()
  log(string.rep("-", 49))
end


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


local function valid_json(arg, ftype)
  local f = io.open(arg, 'r')
  if not f then return false end
  local content = f:read('*all')
  f:close()
  local status, data = json.parse(content)
  if not status or type(data) ~= 'table' then return false end
  if ftype == 'path' then
    if type(data.path) ~= 'table' or type(data.extension) ~= 'table' then
      return false
    end
    registry.path = data
  elseif ftype == 'regex' then
    if type(data.header) ~= 'table'
        or type(data.body) ~= 'table'
        or type(data.external) ~= 'table' then
      return false
    end
    registry.regex = data
  elseif ftype == 'aliases' then
    registry.aliases = data
  elseif ftype == 'vendor_aliases' then
    registry.vendor_aliases = data
  end
  return true
end

local CATALOG_BASE =
'https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/'
local CATALOG_SCHEMA = 1
local MAX_CATALOG_BYTES = 8 * 1024 * 1024
local MAX_CATALOG_RULES = 20000
local MAX_CATALOG_PATHS = 2000
local MAX_CATALOG_PROBES = 500
local MAX_CATALOG_STRING = 2048
local CATALOG_CACHE_DIR = 'data'
local CATALOG_SOURCE_FILE = '.vulners-catalog-source'

local function catalog_file_path(filename)
  return CATALOG_CACHE_DIR .. '/' .. filename
end

local function read_catalog_json(filename)
  local path = catalog_file_path(filename)
  local file = io.open(path, 'rb')
  if not file then return nil end
  -- NSE's lfs module has no attributes(). Bound reads directly instead.
  local body = file:read(MAX_CATALOG_BYTES + 1)
  file:close()
  if type(body) ~= 'string' or #body > MAX_CATALOG_BYTES then
    return nil
  end
  local parsed, data = json.parse(body)
  if not parsed or type(data) ~= 'table' then return nil end
  return data
end

local function fetch_catalog_json(base, filename)
  local ok, response = pcall(http.get_url, base .. filename, {
    timeout = 10000,
    max_body_size = MAX_CATALOG_BYTES,
    any_af = true,
    header = { Accept = 'application/json' }
  })
  if not ok or type(response) ~= 'table'
      or tonumber(response.status) ~= 200 then
    return nil
  end
  local body = response.body or response.rawbody
  if type(body) ~= 'string' or #body > MAX_CATALOG_BYTES then
    return nil
  end
  local parsed, data = json.parse(body)
  if not parsed or type(data) ~= 'table' then return nil end
  return data, body
end

local function class_end(pattern, start)
  local idx = start + 1
  if pattern:sub(idx, idx) == '^' then idx = idx + 1 end
  if pattern:sub(idx, idx) == ']' then idx = idx + 1 end
  while idx <= #pattern do
    local char = pattern:sub(idx, idx)
    if char == '%' then
      idx = idx + 2
    elseif char == ']' then
      return idx
    else
      idx = idx + 1
    end
  end
  return #pattern
end

-- Count the captures of a Lua pattern. Returns nil when the parentheses
-- are unbalanced, because Lua only reports an unfinished capture when a
-- match reaches the end of the pattern with a non-empty subject.
local function capture_count(pattern)
  local captures = 0
  local depth = 0
  local idx = 1
  while idx <= #pattern do
    local char = pattern:sub(idx, idx)
    if char == '%' then
      local escaped = pattern:sub(idx + 1, idx + 1)
      if escaped == 'b' then
        idx = idx + 4
      elseif escaped == 'f' and pattern:sub(idx + 2, idx + 2) == '[' then
        idx = class_end(pattern, idx + 2)
      else
        idx = idx + 2
      end
    elseif char == '[' then
      idx = class_end(pattern, idx)
    else
      if char == '(' then
        captures = captures + 1
        depth = depth + 1
      elseif char == ')' then
        depth = depth - 1
      end
      idx = idx + 1
    end
  end
  if depth ~= 0 then return nil end
  return captures
end

local function valid_pattern(pattern, expected_captures)
  if type(pattern) ~= 'string'
      or #pattern == 0
      or #pattern > MAX_CATALOG_STRING
      or capture_count(pattern) ~= expected_captures then
    return false
  end
  return pcall(string.find, '', pattern)
end

local function valid_alias(alias)
  return type(alias) == 'string'
      and #alias <= 256
      and alias:match('^cpe:/[aoh]:[^:]+:[^:]+$') ~= nil
      and alias:find('[%c]') == nil
end

local function valid_channel(channel)
  if type(channel) ~= 'string' then return false end
  return channel == 'raw'
      or channel == 'body'
      or channel == 'title'
      or channel == 'script'
      or channel == 'cookie'
      or channel == 'banner'
      or channel:match('^hdr:[%w_%-]+$') ~= nil
      or channel:match('^meta:[%w_%-:]+$') ~= nil
end

local function valid_path(path)
  return type(path) == 'string'
      and #path > 0
      and #path <= MAX_CATALOG_STRING
      and path:sub(1, 1) == '/'
      and path:find('[%c%s#]') == nil
end

local function validate_fingerprints(data)
  if type(data.rules) ~= 'table' then return nil end
  local count = 0
  local by_channel = {}
  for name, rule in pairs(data.rules) do
    count = count + 1
    if count > MAX_CATALOG_RULES
        or type(name) ~= 'string'
        or type(rule) ~= 'table'
        or not valid_alias(rule.alias)
        or not valid_channel(rule.channel)
        or not valid_pattern(rule.regex, 1)
        or (rule.anchor ~= nil
          and (type(rule.anchor) ~= 'string'
            or #rule.anchor > MAX_CATALOG_STRING)) then
      return nil
    end
    local channel_rules = by_channel[rule.channel]
    if not channel_rules then
      channel_rules = {}
      by_channel[rule.channel] = channel_rules
    end
    table.insert(channel_rules, {
      alias = rule.alias,
      anchor = rule.anchor,
      regex = rule.regex,
      name = name
    })
  end
  if count == 0 then return nil end
  return by_channel
end

local function validate_paths(data)
  if type(data.paths) ~= 'table' then return nil end
  local paths = {}
  local seen = {}
  for _, path in ipairs(data.paths) do
    if not valid_path(path) then return nil end
    if not seen[path] then
      seen[path] = true
      table.insert(paths, path)
    end
    if #paths > MAX_CATALOG_PATHS then return nil end
  end
  if #paths == 0 then return nil end
  return paths
end

local function validate_probes(data)
  if type(data.probes) ~= 'table'
      or data.schema ~= CATALOG_SCHEMA
      or #data.probes > MAX_CATALOG_PROBES then
    return nil
  end
  local probes = {}
  for _, probe in ipairs(data.probes) do
    if type(probe) ~= 'table'
        or not valid_alias(probe.alias)
        or type(probe.detect) ~= 'table'
        or #probe.detect == 0
        or type(probe.extract) ~= 'table'
        or #probe.extract == 0
        or type(probe.paths) ~= 'table'
        or #probe.paths == 0 then
      return nil
    end
    for _, detector in ipairs(probe.detect) do
      if type(detector) ~= 'table'
          or not valid_channel(detector.channel)
          or type(detector.anchor) ~= 'string'
          or not valid_pattern(detector.regex, 0)
          or #detector.anchor > MAX_CATALOG_STRING then
        return nil
      end
    end
    for _, extractor in ipairs(probe.extract) do
      if type(extractor) ~= 'table'
          or type(extractor.anchor) ~= 'string'
          or not valid_pattern(extractor.regex, 1)
          or #extractor.anchor > MAX_CATALOG_STRING then
        return nil
      end
    end
    local paths = {}
    for _, path in ipairs(probe.paths) do
      if not valid_path(path) then return nil end
      table.insert(paths, path)
    end
    table.insert(probes, {
      alias = probe.alias,
      detect = probe.detect,
      extract = probe.extract,
      paths = paths,
      name = probe.name
    })
  end
  return probes
end

local function build_catalog(index, load_json)
  if not index or index.schema ~= CATALOG_SCHEMA
      or type(index.catalogs) ~= 'table' then
    return nil
  end
  local files = {
    fingerprints = 'fingerprints.json',
    paths = 'paths.json',
    probes = 'probes.json'
  }
  local loaded = {}
  for kind, filename in pairs(files) do
    local descriptor = index.catalogs[kind]
    if type(descriptor) ~= 'table' or descriptor.file ~= filename then
      return nil
    end
    local data = load_json(filename)
    if not data then return nil end
    if kind == 'fingerprints' then
      loaded.fingerprints = validate_fingerprints(data)
    elseif kind == 'paths' then
      loaded.paths = validate_paths(data)
    else
      loaded.probes = validate_probes(data)
    end
    if not loaded[kind] then return nil end
  end
  return loaded
end

local function read_catalog_source()
  local file = io.open(catalog_file_path(CATALOG_SOURCE_FILE), 'r')
  if not file then return nil end
  local source = file:read('*all')
  file:close()
  return source
end

local function load_catalog_cache(base)
  if read_catalog_source() ~= base then return false end
  local index = read_catalog_json('index.json')
  local loaded = build_catalog(index, read_catalog_json)
  if not loaded then return false end
  registry.catalog = loaded
  registry.catalog_loaded = true
  stdnse.verbose(1, fmt('Using cached Vulners catalogue from %s.',
    CATALOG_CACHE_DIR))
  return true
end

local function ensure_catalog_cache_dir()
  local created = lfs.mkdir(CATALOG_CACHE_DIR)
  if created then return true end
  -- mkdir also fails when the directory already exists. dir() distinguishes
  -- that case from a file or an inaccessible path using NSE's supported API.
  local readable, iterator = pcall(lfs.dir, CATALOG_CACHE_DIR)
  return readable and type(iterator) == 'function'
end

local function write_catalog_file(filename, body)
  local file = io.open(catalog_file_path(filename), 'wb')
  if not file then return false end
  local written = file:write(body)
  local closed = file:close()
  return written ~= nil and closed ~= nil
end

local function save_catalog_cache(base, files)
  if not ensure_catalog_cache_dir() then return false end
  os.remove(catalog_file_path(CATALOG_SOURCE_FILE))
  for filename, body in pairs(files) do
    if not write_catalog_file(filename, body) then return false end
  end
  return write_catalog_file(CATALOG_SOURCE_FILE, base)
end

local function load_catalog()
  if catalog_arg == 'none' then return false end
  local base = catalog_url_arg or CATALOG_BASE
  if base:match('^https?://[^/%s]+') == nil then
    stdnse.verbose(1, 'Invalid catalogue URL; using local legacy data.')
    return false
  end
  if base:sub(-1) ~= '/' then base = base .. '/' end

  if load_catalog_cache(base) then return true end

  local index, index_body = fetch_catalog_json(base, 'index.json')
  if not index or not index_body then return false end
  local cache_files = { ['index.json'] = index_body }
  local loaded = build_catalog(index, function(filename)
    local data, body = fetch_catalog_json(base, filename)
    if data and body then cache_files[filename] = body end
    return data
  end)
  if not loaded then return false end

  registry.catalog = loaded
  registry.catalog_loaded = true
  if save_catalog_cache(base, cache_files) then
    stdnse.verbose(1, fmt('Cached Vulners catalogue in %s.',
      CATALOG_CACHE_DIR))
  else
    stdnse.verbose(1, fmt('Could not cache Vulners catalogue in %s.',
      CATALOG_CACHE_DIR))
  end
  return true
end

local function load_legacy_catalog()
  if not exists(path_arg) or not exists(regex_arg) then return false end
  if not valid_json(path_arg, 'path')
      or not valid_json(regex_arg, 'regex') then
    return false
  end
  registry.legacy_catalog = true
  return true
end


local function load_platform_families()
  local families = read_catalog_json('platform-families.json')
  if families == nil then
    stdnse.verbose(1, 'Platform families unavailable; OS context disabled.')
    return {}
  end
  return families
end


local function required_files()
  local ret = ""
  if not exists(db_arg) then
    ret = fmt("Database %s could not be read. " ..
      "Run uv run --project db-manager db-manager " ..
      "before running nmap script.",
      db_arg)
  else
    registry.aliases = {}
    if exists(aliases_arg) and not valid_json(aliases_arg, 'aliases') then
      stdnse.verbose(1, fmt('Invalid aliases file %s; skipping aliases.',
        aliases_arg))
    end
    registry.vendor_aliases = {}
    if exists(vendor_aliases_arg)
        and not valid_json(vendor_aliases_arg, 'vendor_aliases') then
      stdnse.verbose(1, fmt(
        'Invalid vendor aliases file %s; skipping vendor aliases.',
        vendor_aliases_arg))
    end
    registry.platform_families = load_platform_families()
    if http_arg == '1' and catalog_arg ~= 'none' then
      if not load_catalog() and not load_legacy_catalog() then
        stdnse.verbose(1,
          'HTTP catalogue unavailable; continuing with Nmap CPEs.')
      end
    end
  end
  return ret
end


local function add_cpe_version(cpe, version, matches, location)
  if version:sub(-1) == '.' then -- strip dot at the end of version
    version = version:sub(1, -2)
  end
  if matches['data'][location][cpe] == nil then
    matches['data'][location][cpe] = {}
  end
  if matches['data'][location][cpe][version] == nil then
    stdnse.verbose(2, location .. " cpe: " .. cpe .. " | version: " .. version)
    matches['data'][location][cpe][version] = true
    matches['size'] = matches['size'] + 1
    return true
  end
end


local function split_cpe(cpe)
  local parts = {}
  local field = {}
  local escaped = false
  for i = 1, #cpe do
    local char = cpe:sub(i, i)
    if char == ':' and not escaped then
      table.insert(parts, table.concat(field))
      field = {}
    else
      table.insert(field, char)
      if char == '\\' and not escaped then
        escaped = true
      else
        escaped = false
      end
    end
  end
  table.insert(parts, table.concat(field))

  local offset
  if parts[1] == 'cpe' and parts[2] == '2.3' then
    offset = 3
  elseif parts[1] == 'cpe' and parts[2] and parts[2]:sub(1, 1) == '/' then
    offset = 2
  else
    return nil
  end

  local function unescape(value)
    return (value or ''):gsub('\\(.)', '%1')
  end
  local cpe_type = unescape(parts[offset])
  if cpe_type:sub(1, 1) == '/' then
    cpe_type = cpe_type:sub(2)
  end
  return parts, offset, cpe_type,
      unescape(parts[offset + 1]),
      unescape(parts[offset + 2]),
      unescape(parts[offset + 3]),
      unescape(parts[offset + 4])
end


local function add_cpe_aliases(cpe, version, matches, location)
  local parts, offset, _, _, product = split_cpe(cpe)
  if not parts then return end
  local product_index = offset + 2
  -- Product aliases
  if registry.aliases[product] then
    for _, alias in pairs(registry.aliases[product]) do
      parts[product_index] = alias
      add_cpe_version(table.concat(parts, ":"), version, matches, location)
    end
  end
end


local function find_version(cpe, text, regex, matches)
  local idx = 0
  local sidx = 0
  local version
  while true do
    sidx, idx, version = text:find(regex, idx + 1)
    if version then
      if version == '' then
        version = '*'
      end
      local msg = add_cpe_version(cpe, version, matches, 'http')
      if msg then
        stdnse.verbose(2, "http find_version matched text: " ..
          text:sub(sidx, idx) ..
          " | version: " .. version)
      end
    end
    if idx == nil then break end
  end
end


local function regex_match(text, location, matches)
  for _, software in pairs(registry.regex[location]) do
    if type(software.regex) == 'table' then
      for _, regex in pairs(software.regex) do
        find_version(software.cpe, text, regex, matches)
      end
    else
      find_version(software.cpe, text, software.regex, matches)
    end
  end
end

local function http_match_legacy(host, port, matches)
  for _, path in pairs(registry.path['path']) do
    for _, ext in pairs(registry.path['extension']) do
      local file = "/" .. path .. ext
      if (path == '' and ext == '') or path ~= '' then
        local resp = http.get(host, port, file,
          {
            redirect_ok = maxredirect_arg,
            timeout = 10000,
            max_body_size = 131072,
            truncated_ok = true,
            bypass_cache = true,
            no_cache = true,
            no_cache_body = true
          }
        )
        if not resp.status then
          stdnse.verbose(2, fmt("Error processing request http://%s:%s%s => %s",
            host.ip, port.number, file, resp['status-line']))
        else
          local rawbody = resp.rawbody or ''
          if resp.rawheader and #resp.rawheader > 0 then
            for _, header in pairs(resp.rawheader) do
              regex_match(header, 'header', matches)
            end
          end
          if rawbody ~= '' then
            regex_match(rawbody, 'body', matches)
          end
        end
        if path == '' and ext == '' and resp.status then
          local rawbody = resp.rawbody or ''
          local idx = 0
          local lib_path = nil
          local libs = { ['size'] = 0 }
          while true do
            _, idx, lib_path = rawbody:find(
              registry.regex['external']['path_regex'], idx + 1)
            if lib_path and lib_path:sub(1, 1) == '/' then
              local lib_resp = http.get(host, port, lib_path,
                {
                  redirect_ok = maxredirect_arg,
                  timeout = 10000,
                  max_body_size = 131072,
                  truncated_ok = true,
                  bypass_cache = true,
                  no_cache = true,
                  no_cache_body = true
                }
              )
              if lib_resp.status and lib_resp.rawbody ~= nil then
                local _, _, lib_comm = lib_resp.rawbody:find(
                  registry.regex['external']['comment_regex'])
                if lib_comm then
                  stdnse.verbose(3, "Comment: " .. lib_comm)
                  local idy = 0
                  local comm_lib = nil
                  local comm_ver = nil
                  while true do
                    _, idy, comm_lib, comm_ver = lib_comm:find(
                      registry.regex['external']['version_regex'],
                      idy + 1)
                    if comm_lib and comm_ver then
                      if comm_lib:lower() ~= 'version' then
                        stdnse.verbose(2,
                          "Matched version in js " ..
                          "comment: " .. comm_lib ..
                          " ver: " .. comm_ver)
                        libs[comm_lib] = comm_ver
                        libs['size'] = libs['size'] + 1
                      end
                    end
                    if idy == nil then break end
                  end
                end
              end
            end
            if idx == nil then break end
          end
          if libs['size'] > 0 then
            for name, data in pairs(registry.regex['body']) do
              for k, v in pairs(libs) do
                if k ~= 'size' then
                  local k_stripped = (k:gsub('%.js$', '')):lower()
                  if (name:lower()):find(k_stripped, 1, true) then
                    add_cpe_version(data['cpe'], v, matches, 'http')
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end

local function add_subject(subjects, channel, value)
  if type(value) ~= 'string' or value == '' then return end
  if not subjects[channel] then subjects[channel] = {} end
  table.insert(subjects[channel], value)
end

local function case_insensitive_pattern(value)
  local pattern = value:gsub('%a', function(char)
    return '[' .. char:lower() .. char:upper() .. ']'
  end)
  return pattern
end

local function html_attribute(tag, name)
  local pattern = case_insensitive_pattern(name)
  local value = tag:match(pattern .. '%s*=%s*"([^"]*)"')
  if value then return value end
  value = tag:match(pattern .. "%s*=%s*'([^']*)'")
  if value then return value end
  return tag:match(pattern .. '%s*=%s*([^%s>]+)')
end

local function response_subjects(response)
  local subjects = {}
  local raw_headers = response.rawheader
  if type(raw_headers) == 'table' then
    add_subject(subjects, 'raw', table.concat(raw_headers, '\n'))
  end
  local headers = response.header
  if type(headers) == 'table' then
    for name, value in pairs(headers) do
      local channel = 'hdr:' .. tostring(name):lower()
      if type(value) == 'string' then
        add_subject(subjects, channel, value)
      elseif type(value) == 'table' then
        for _, item in ipairs(value) do
          add_subject(subjects, channel, item)
        end
      end
    end
  end
  local cookies = response.cookies
  if type(cookies) == 'table' then
    for _, cookie in ipairs(cookies) do
      if type(cookie) == 'table' then
        if type(cookie.name) == 'string'
            and type(cookie.value) == 'string' then
          add_subject(subjects, 'cookie',
            cookie.name .. '=' .. cookie.value)
        end
      end
    end
  end

  local body = response.body
  if type(body) ~= 'string' then body = '' end
  add_subject(subjects, 'body', body)
  for title in body:gmatch(
    '<[tT][iI][tT][lL][eE][^>]*>(.-)</[tT][iI][tT][lL][eE]%s*>') do
    add_subject(subjects, 'title', title)
  end
  for tag in body:gmatch('<[mM][eE][tT][aA][^>]*>') do
    local name = html_attribute(tag, 'name') or
        html_attribute(tag, 'property')
    local content = html_attribute(tag, 'content')
    if name and content then
      add_subject(subjects, 'meta:' .. name:lower(), content)
    end
  end
  for tag in body:gmatch('<[sS][cC][rR][iI][pP][tT][^>]*>') do
    add_subject(subjects, 'script', html_attribute(tag, 'src'))
  end
  return subjects
end

local function response_is_usable(response)
  local status = tonumber(response.status)
  return status ~= nil and status >= 200 and status < 400
end

local function safe_version(value)
  if type(value) ~= 'string' or #value == 0 or #value > 128
      or value:find('[%c]') ~= nil then
    return nil
  end
  value = value:gsub('^%s+', ''):gsub('%s+$', '')
  if value == '' or value == '*' or value:find('%w') == nil then
    return nil
  end
  return value
end

local function pattern_match(pattern, subject)
  local ok, first, last, capture = pcall(string.find, subject, pattern)
  if not ok or first == nil or last == nil then return nil end
  return capture
end

local function anchor_matches(anchor, subject)
  return type(anchor) ~= 'string'
      or anchor == ''
      or subject:lower():find(anchor:lower(), 1, true) ~= nil
end

local function anchored_capture(pattern, anchor, subject)
  if not anchor or anchor == ''
      or pattern:sub(1, 1) == '^' or pattern:sub(-1) == '$' then
    return safe_version(pattern_match(pattern, subject))
  end
  local lower_subject = subject:lower()
  local lower_anchor = anchor:lower()
  local offset = 1
  local hits = 0
  while hits < 8 do
    local position = lower_subject:find(lower_anchor, offset, true)
    if not position then return nil end
    hits = hits + 1
    local first = math.max(1, position - 256)
    local last = math.min(#subject, position + #anchor + 512)
    local window = subject:sub(first, last)
    local version = safe_version(pattern_match(pattern, window))
    if version then return version end
    offset = position + math.max(1, #lower_anchor)
  end
  return nil
end

local function match_fingerprint_rule(rule, subject, matches, location)
  if not anchor_matches(rule.anchor, subject) then return false end
  local version = anchored_capture(rule.regex, rule.anchor, subject)
  if not version then return false end
  add_cpe_version(rule.alias, version, matches, location)
  return true
end

local function pattern_found(pattern, anchor, subject)
  if not anchor or anchor == ''
      or pattern:sub(1, 1) == '^' or pattern:sub(-1) == '$' then
    local ok, first = pcall(string.find, subject, pattern)
    return ok and first ~= nil
  end
  local lower_subject = subject:lower()
  local lower_anchor = anchor:lower()
  local offset = 1
  local hits = 0
  while hits < 8 do
    local position = lower_subject:find(lower_anchor, offset, true)
    if not position then return false end
    hits = hits + 1
    local first = math.max(1, position - 256)
    local last = math.min(#subject, position + #anchor + 512)
    local ok, match = pcall(string.find, subject:sub(first, last), pattern)
    if ok and match ~= nil then return true end
    offset = position + math.max(1, #lower_anchor)
  end
  return false
end

local function probe_detects(probe, subjects)
  for _, detector in ipairs(probe.detect) do
    local values = subjects[detector.channel] or {}
    for _, subject in ipairs(values) do
      if anchor_matches(detector.anchor, subject)
          and pattern_found(detector.regex, detector.anchor, subject) then
        return true
      end
    end
  end
  return false
end

local function match_subjects(subjects, matches, location, triggered)
  if not registry.catalog_loaded then return end
  for channel, values in pairs(subjects) do
    local rules = registry.catalog.fingerprints[channel] or {}
    for _, subject in ipairs(values) do
      for _, rule in ipairs(rules) do
        match_fingerprint_rule(rule, subject, matches, location)
      end
    end
  end
  for _, probe in ipairs(registry.catalog.probes) do
    if not triggered[probe.alias] and probe_detects(probe, subjects) then
      triggered[probe.alias] = true
    end
  end
end

local function match_banner(port, matches, triggered)
  if not registry.catalog_loaded or not port.version then return end
  local banner = port.version.service_fp
  if type(banner) ~= 'string' or banner == '' then return end
  local subjects = { banner = {} }
  for line in banner:gmatch('[^\r\n]+') do
    table.insert(subjects.banner, line)
  end
  match_subjects(subjects, matches, 'nmap', triggered)
end

local function options_for_target()
  return {
    redirect_ok = maxredirect_arg,
    timeout = 10000,
    max_body_size = 131072,
    truncated_ok = true,
    bypass_cache = true,
    no_cache = true,
    no_cache_body = true
  }
end

local function cpe_has_version(matches, cpe)
  for _, source in pairs(matches.data) do
    if source[cpe] and next(source[cpe]) ~= nil then return true end
  end
  return false
end

local function is_series_version(version)
  return version:match('^%d+%.%d+$') ~= nil
    or version:match('%.[xX]$') ~= nil
    or version:match('%.%*$') ~= nil
end

local function is_precise_version(version)
  return not is_series_version(version)
    and version:find('%s+%-%s+') == nil
end

local function cpe_has_precise_version(matches, cpe)
  for _, source in pairs(matches.data) do
    for version in pairs(source[cpe] or {}) do
      if is_precise_version(version) then return true end
    end
  end
  return false
end

local function prune_series_versions(matches, cpe, version)
  for _, source in pairs(matches.data) do
    local versions = source[cpe]
    if versions then
      for series in pairs(versions) do
        if is_series_version(series)
            and version:sub(1, #series + 1) == series .. '.' then
          versions[series] = nil
          matches.size = matches.size - 1
        end
      end
    end
  end
end

local function probe_version(probe, body)
  for _, extractor in ipairs(probe.extract) do
    if anchor_matches(extractor.anchor, body) then
      local version = anchored_capture(extractor.regex,
        extractor.anchor, body)
      if version then return version end
    end
  end
  return nil
end

local function run_targeted_probes(host, port, matches, triggered)
  local probes_used = 0
  for _, probe in ipairs(registry.catalog.probes) do
    if triggered[probe.alias]
        and not cpe_has_precise_version(matches, probe.alias)
        and probes_used < 3 then
      probes_used = probes_used + 1
      local paths_used = 0
      for _, path in ipairs(probe.paths) do
        if paths_used >= 3
            or cpe_has_precise_version(matches, probe.alias) then
          break
        end
        paths_used = paths_used + 1
        local response = http.get(host, port, path, options_for_target())
        if type(response) == 'table' and response_is_usable(response) then
          local body = response.body
          if type(body) == 'string' then
            local version = probe_version(probe, body)
            if version then
              add_cpe_version(probe.alias, version, matches, 'http')
              if is_precise_version(version) then
                prune_series_versions(matches, probe.alias, version)
              end
            end
          end
        end
      end
    end
  end
end

local function sweep_catalog(host, port, matches, triggered)
  local pace = {
    [0] = { 5, 2.0 },
    [1] = { 10, 1.0 },
    [2] = { 25, 0.5 },
    [3] = { 100, 0.1 },
    [4] = { 250, 0 },
    [5] = { 250, 0 }
  }
  local setting = pace[nmap.timing_level()] or pace[3]
  local batch_size = setting[1]
  local delay = setting[2]
  local paths = registry.catalog.paths
  local start = 1
  while start <= #paths do
    local requests = nil
    local finish = math.min(start + batch_size - 1, #paths)
    for idx = start, finish do
      requests = http.pipeline_add(paths[idx], options_for_target(),
        requests)
    end
    local responses = http.pipeline_go(host, port, requests)
    if type(responses) == 'table' then
      for idx, response in ipairs(responses) do
        if type(response) == 'table' and maxredirect_arg > 0 then
          local status = tonumber(response.status)
          if status == 301 or status == 302 or status == 303
              or status == 307 or status == 308 then
            -- Pipelines do not follow redirects. Reissue this path through
            -- get() to apply Nmap's redirect checks and maxredirect limit.
            response = http.get(host, port, paths[start + idx - 1],
              options_for_target())
          end
        end
        if type(response) == 'table' and response_is_usable(response) then
          match_subjects(response_subjects(response), matches,
            'http', triggered)
        end
      end
    end
    start = finish + 1
    if delay > 0 and start <= #paths then stdnse.sleep(delay) end
  end
end

local function http_match(host, port, matches, triggered)
  if registry.catalog_loaded then
    sweep_catalog(host, port, matches, triggered)
    run_targeted_probes(host, port, matches, triggered)
  elseif registry.legacy_catalog then
    http_match_legacy(host, port, matches)
  end
end


-- Words that make a dash suffix a pre-release instead of a build tag.
local PRERELEASE_WORDS = {
  alpha = true, beta = true, rc = true, pre = true, preview = true, dev = true,
}

-- Drop a build or distro tag (-log, -3ubuntu5) from a version suffix.
-- The suffix is kept when its dash introduces a known pre-release (-rc1).
local function strip_build_suffix(suffix)
  local head, tail = suffix:match('^([^%-]*)(%-.*)$')
  if not head then return suffix end
  local word = tail:match('^%-(%a+)')
  if word and PRERELEASE_WORDS[word:lower()] then return suffix end
  return head
end


local function version_parser(product, version, cpe_update)
  if version then
    -- remove Nmap comment of version
    version = version:gsub('for_windows_', '')
    -- remove a leading 'v' before the number (v1.2.3 -> 1.2.3)
    version = version:gsub('^[vV](%d)', '%1')
  end

  -- if Nmap could not detect version, assume all versions and vupdates possible
  if version == '-' then
    return product, {
      ver = '-',
      vup = '-',
      from = nil,
      to = nil,
      empty = false,
      range = false
    }
  end
  if empty(version) or version == '*' then
    return product, {
      ver = '*',
      vup = '*',
      from = nil,
      to = nil,
      empty = true,
      range = false
    }
  end

  -- if version matches patterns: 3.x - 4.x | 3.3.x - 3.4.x ...
  local p1, p2 = version:match('^(.-)%s+%-%s+(.+)$')
  if not empty(p1) and not empty(p2) then
    local f1, f2 = p1:match('([^%a]*)(.*)')
    local t1, t2 = p2:match('([^%a]*)(.*)')
    return product, {
      ver = nil,
      vup = nil,
      from = f1 .. f2,
      to = t1 .. t2,
      empty = false,
      range = true
    }
  end

  -- Treat a trailing x as an unknown patch component (for example, 2.4.x).
  local wildcard_prefix = version:match('^([%d%.]+)[xX]$')
  if wildcard_prefix then
    return product, {
      ver = nil,
      vup = nil,
      from = wildcard_prefix .. '0',
      to = wildcard_prefix .. '9999999999',
      empty = false,
      range = true
    }
  end

  -- If version matches patterns: 4.3 | 4.3p1 | 4.3.1sp1 ...
  p1, p2 = version:match('^([%d%.]+)(.*)$')
  if p1 then
    p2 = strip_build_suffix(p2)
    if p2:sub(1, 1) == '-' then
      p1 = p1 .. p2
      p2 = ''
    end
    if cpe_update and cpe_update ~= '' and cpe_update ~= '*'
        and cpe_update ~= '-' then
      p2 = cpe_update
    elseif empty(p2) then
      p2 = cpe_update == '-' and '-' or '*'
    end
    return product, {
      ver = p1,
      vup = p2,
      from = nil,
      to = nil,
      empty = false,
      range = false
    }
  end

  return product, {
    ver = '*',
    vup = '*',
    from = nil,
    to = nil,
    empty = true,
    range = false
  }
end


local function prefer_version(cpe_version, nmap_version)
  if empty(nmap_version) or nmap_version == '*' then
    return cpe_version, 'nmap_cpe'
  end
  if empty(cpe_version) or cpe_version == '*' then
    return nmap_version, 'nmap_version'
  end
  if nmap_version:match('^(.-)%s+%-%s+(.+)$') then
    return nmap_version, 'nmap_version'
  end
  if nmap_version:sub(1, #cpe_version + 1) == cpe_version .. '.' then
    return nmap_version, 'nmap_version'
  end
  return cpe_version, 'nmap_cpe'
end


local function cpe_parser(cpe, version)
  local _, _, _, vendor, product, cpe_version, cpe_update = split_cpe(cpe)
  if not product then return nil, nil, nil end

  local source
  cpe_version, source = prefer_version(cpe_version, version)
  if source == 'nmap_version' then
    cpe_update = nil
  end

  local parsed_product, info = version_parser(product, cpe_version, cpe_update)
  return vendor, parsed_product, info, source
end


local function query(qtype)
  if qtype == 'cve_score' then
    return [[
             SELECT cvss_v2, cvss_v3
             FROM cves
             WHERE cve_id = '%s'
             ]]
  elseif qtype == 'exploit_info' then
    return [[
             SELECT exploits.exploit_id, exploits.name
             FROM referenced_exploit
             INNER JOIN exploits ON referenced_exploit.exploit_id = exploits.exploit_id
             WHERE referenced_exploit.cve_id = '%s'
             ]]
  elseif qtype == 'metasploit_info' then
    return [[
             SELECT metasploits.name
             FROM referenced_metasploit
             INNER JOIN metasploits ON referenced_metasploit.metasploit_id = metasploits.metasploit_id
             WHERE referenced_metasploit.cve_id = '%s'
             ]]
  elseif qtype == 'multiaffected' then
    return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             multiaffected.versionStartIncluding, multiaffected.versionStartExcluding,
             multiaffected.versionEndIncluding, multiaffected.versionEndExcluding,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id IN
             (SELECT product_id FROM products WHERE vendor IN (${v}) AND product = '${p}' AND version = '*')
             ]]
  elseif qtype == 'multiaffected_empty' then
    return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             multiaffected.versionStartIncluding, multiaffected.versionStartExcluding,
             multiaffected.versionEndIncluding, multiaffected.versionEndExcluding,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id IN
             (SELECT product_id FROM products WHERE vendor IN (${v}) AND product = '${p}' AND version = '*' and version_update = '*')
             AND versionStartIncluding IS NULL AND versionStartExcluding IS NULL
             AND versionEndIncluding IS NULL AND versionEndExcluding IS NULL
             ]]
  elseif qtype == 'product_vendors' then
    return [[
             SELECT DISTINCT vendor FROM products
             WHERE product = '${p}'
             ]]
  elseif qtype == 'series_children' then
    return [[
             SELECT EXISTS (SELECT 1 FROM products
             WHERE vendor IN (${v}) AND product = '${p}'
             AND version LIKE '${s}.%')
             ]]
  elseif qtype == 'platform_conditions' then
    return [[
             SELECT DISTINCT conditions.cve_id, conditions.config_idx,
             conditions.part, conditions.vendor, conditions.product
             FROM conditions
             INNER JOIN products ON conditions.product_id = products.product_id
             WHERE products.vendor IN (${v}) AND products.product = '${p}'
             ]]
  elseif qtype == 'affected' then
    return [[
             SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
             products.version, products.version_update,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = affected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = affected.cve_id)) as msf
             FROM products
             INNER JOIN affected ON products.product_id = affected.product_id
             INNER JOIN cves ON affected.cve_id = cves.cve_id
             WHERE products.vendor IN (${v}) AND products.product = '${p}'
             ]]
  end
end


-- Store one CVE in the JSON report and, when show is true, in the log.
local function dump_exploit(host, port, vuln, rec, show)
  local _ip = host.ip
  local _port = fmt('%s/%s', port.number, port.protocol)
  local emit = show and log or function() end
  local reasons = #rec.reasons > 0 and table.concat(rec.reasons, ', ') or '-'
  -- Dump the CVE score
  local cur = registry.conn:execute(
    fmt(query('cve_score'), vuln)
  )
  local cvssv2, cvssv3 = cur:fetch()
  cur:close()
  emit("[-] \tid: %-18s\tcvss_v2: %-5s\tcvss_v3: %-5s", vuln, cvssv2,
    cvssv3 or "-")
  emit("[-] \tconfidence: %s\treasons: %s", rec.confidence, reasons)
  local t_serv = #registry.json_out[_ip]['ports'][_port]['services']
  registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln] = {
    ['cvssv2'] = cvssv2,
    ['cvssv3'] = cvssv3 or "-",
    ['confidence'] = rec.confidence,
    ['reasons'] = rec.reasons,
  }

  -- Dump exploits from Exploit-DB
  cur = registry.conn:execute(
    fmt(query('exploit_info'), vuln)
  )
  local exploit, name = cur:fetch()
  if exploit then
    emit("[!] \t\tExploitDB:")
    registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]['exploitdb'] = {}
    local exp_list = registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]
        ['exploitdb']
    while exploit do
      emit("[#] \t\t\tname: %s", name)
      emit("[#] \t\t\tid: %s", exploit)
      emit("[#] \t\t\turl: https://www.exploit-db.com/exploits/%s", exploit)
      exp_list[#exp_list + 1] = {
        ['name'] = name,
        ['id'] = exploit,
        ['url'] = fmt('https://www.exploit-db.com/exploits/%s', exploit)
      }
      exploit, name = cur:fetch()
    end
  end
  cur:close()

  -- Dump exploits from Metasploit
  cur = registry.conn:execute(
    fmt(query('metasploit_info'), vuln)
  )
  name = cur:fetch()
  if name then
    emit("[!] \t\tMetasploit:")
    registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]['metasploit'] = {}
    local meta_list = registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]
        ['metasploit']
    while name do
      emit("[#] \t\t\tname: %s", name)
      meta_list[#meta_list + 1] = { ['name'] = name }
      name = cur:fetch()
    end
  end
  cur:close()
end


local function cvss_comparator(a, b)
  local score_a = tonumber(a[3]) or tonumber(a[2]) or -1
  local score_b = tonumber(b[3]) or tonumber(b[2]) or -1
  if score_a == score_b then return a[1] < b[1] end
  return score_a > score_b
end


local function split_version(str)
  local parts = {}
  for part in string.gmatch(str, "([^.]+)") do
    table.insert(parts, part)
  end
  return parts
end


local function compare_version(version1, version2)
  if version1 == nil or version2 == nil then return nil end
  if version1 == version2 and (version1 == '-' or version1 == '*') then
    return 0
  end
  local numeric1 = tostring(version1):match('^[%d%.]+')
  local numeric2 = tostring(version2):match('^[%d%.]+')
  if not numeric1 or not numeric1:find('%d')
      or not numeric2 or not numeric2:find('%d') then
    return nil
  end
  local parts1 = split_version(numeric1)
  local parts2 = split_version(numeric2)
  local max_len = math.max(#parts1, #parts2)
  for i = 1, max_len do
    local num1 = tonumber(parts1[i]) or 0
    local num2 = tonumber(parts2[i]) or 0
    if num1 < num2 then
      return -1
    elseif num1 > num2 then
      return 1
    end
  end

  local suffix1 = strip_build_suffix(
    tostring(version1):sub(#numeric1 + 1):lower())
  local suffix2 = strip_build_suffix(
    tostring(version2):sub(#numeric2 + 1):lower())
  if suffix1 == suffix2 then return 0 end

  local function prerelease(suffix)
    suffix = suffix:gsub('^[%._%-]+', '')
    return suffix:match('^a%d[%d%.%-]*$') ~= nil
        or suffix:match('^alpha[%d%.%-]*$') ~= nil
        or suffix:match('^b%d[%d%.%-]*$') ~= nil
        or suffix:match('^beta[%d%.%-]*$') ~= nil
        or suffix:match('^pre[%d%.%-]*$') ~= nil
        or suffix:match('^preview[%d%.%-]*$') ~= nil
        or suffix:match('^rc[%d%.%-]*$') ~= nil
        or suffix:match('^dev[%d%.%-]*$') ~= nil
  end
  if suffix1 == '' then return prerelease(suffix2) and 1 or -1 end
  if suffix2 == '' then return prerelease(suffix1) and -1 or 1 end
  local normalized1 = suffix1:gsub('^[%._%-]+', '')
  local normalized2 = suffix2:gsub('^[%._%-]+', '')
  local name1, number1 = normalized1:match('^([%a]+)(%d+)$')
  local name2, number2 = normalized2:match('^([%a]+)(%d+)$')
  if name1 ~= nil and name1 == name2 and number1 and number2 then
    number1 = number1:gsub('^0+', '')
    number2 = number2:gsub('^0+', '')
    if #number1 < #number2 then return -1 end
    if #number1 > #number2 then return 1 end
    if number1 < number2 then return -1 end
    if number1 > number2 then return 1 end
    return 0
  end
  if suffix1 < suffix2 then return -1 end
  return 1
end


local function default_version(version, default)
  if version == nil or version == '' then
    return default
  else
    return version
  end
end


local function add_scoped_vulnerability(v, result, reason)
  if result[v.id] == nil then
    result[v.id] = {
      ['CVSSV2'] = v.CVSSV2,
      ['CVSSV3'] = v.CVSSV3,
      ['ExploitDB'] = v.ExploitDB,
      ['Metasploit'] = v.Metasploit,
      ['reasons'] = reason and { reason } or {}
    }
  end
end


-- True when the NVD row has at least one version bound.
local function is_bounded(v)
  return v.StartInc ~= nil or v.StartExc ~= nil
      or v.EndInc ~= nil or v.EndExc ~= nil
end


-- True when the NVD row interval contains the whole observed interval.
local function range_contains(v, from, to)
  local cmp
  if v.StartInc ~= nil then
    cmp = compare_version(v.StartInc, from)
    if cmp == nil or cmp > 0 then return false end
  end
  if v.StartExc ~= nil then
    cmp = compare_version(v.StartExc, from)
    if cmp == nil or cmp >= 0 then return false end
  end
  if v.EndInc ~= nil then
    cmp = compare_version(v.EndInc, to)
    if cmp == nil or cmp < 0 then return false end
  end
  if v.EndExc ~= nil then
    cmp = compare_version(v.EndExc, to)
    if cmp == nil or cmp <= 0 then return false end
  end
  return true
end


-- Return the reason of a matched NVD range row.
local function multi_reason(v, from, to)
  if not is_bounded(v) then return 'nvd_unbounded' end
  if range_contains(v, from, to) then return 'range_contains' end
  return 'range_overlap'
end


local function scoped_multi_versions(all_versions, from, to, result, unknown_version)
  for _, v in pairs(all_versions) do
    if unknown_version then
      -- The corresponding SQL query already limits these to unbounded
      -- NVD ranges, so no version comparison is possible or necessary.
      add_scoped_vulnerability(v, result, 'nvd_unbounded')
    else
      local applies = true
      local cmp
      if v.StartInc ~= nil then
        cmp = compare_version(v.StartInc, to)
        applies = cmp ~= nil and cmp <= 0
      end
      if applies and v.StartExc ~= nil then
        cmp = compare_version(v.StartExc, to)
        applies = cmp ~= nil and cmp < 0
      end
      if applies and v.EndInc ~= nil then
        cmp = compare_version(v.EndInc, from)
        applies = cmp ~= nil and cmp >= 0
      end
      if applies and v.EndExc ~= nil then
        cmp = compare_version(v.EndExc, from)
        applies = cmp ~= nil and cmp > 0
      end
      -- Report a range-based CVE only when the NVD interval overlaps the
      -- version interval Nmap reported. Exclusive boundaries stay strict.
      if applies then
        add_scoped_vulnerability(v, result, multi_reason(v, from, to))
      end
    end
  end
end


-- True when an NVD update is a concrete update, not '*', '-' or empty.
local function concrete_update(update)
  return update ~= '*' and update ~= '-' and update ~= ''
end


-- Return the reason of an exact row. A concrete row update with an
-- unknown observed update is only medium confidence.
local function exact_reason(pr_vu, upd)
  if upd == '*' and concrete_update(pr_vu) then return 'update_unknown' end
  return 'exact_version'
end


local function scoped_versions(all_versions, from, to, upd, result)
  for _, v in pairs(all_versions) do
    local pr_v = default_version(v.version, '0')
    local pr_vu = default_version(v.version_update, '*')
    local applies = false
    local reason = nil
    if from ~= to then
      local affected_version = pr_v
      if pr_vu ~= '*' and pr_vu ~= '-' and pr_vu ~= '' then
        affected_version = affected_version .. pr_vu
      end
      local lower = compare_version(affected_version, from)
      local upper = compare_version(affected_version, to)
      applies = lower ~= nil and lower >= 0
          and upper ~= nil and upper <= 0
    else
      local observed_full = from
      if upd ~= nil and upd ~= '*' and upd ~= '-' then
        observed_full = from .. upd
      end
      local base = compare_version(pr_v, from)
      local full = compare_version(pr_v, observed_full)
      local update_matches = pr_vu == upd or pr_vu == '*' or upd == '*'
      applies = (base == 0 or full == 0) and update_matches
      reason = exact_reason(pr_vu, upd)
    end
    if applies then add_scoped_vulnerability(v, result, reason) end
  end
end



-- Distinct vendors that have rows for product in the database.
local function product_vendors(product)
  local cur = registry.conn:execute(
    fmtn(query('product_vendors'), { p = product }))
  local names = {}
  local name = cur:fetch()
  while name do
    table.insert(names, name)
    name = cur:fetch()
  end
  cur:close()
  return names
end


-- Vendor names to query: Nmap's vendor plus its NVD aliases. When none of
-- them has this product, every vendor with the product is used instead,
-- which is the same as searching by product alone.
local function vendor_scope(vendor, product)
  local names = { vendor }
  local aliases = registry.vendor_aliases[vendor]
  if type(aliases) == 'table' then
    for _, alias in ipairs(aliases) do
      table.insert(names, alias)
    end
  end
  local known = product_vendors(product)
  local present = {}
  for _, name in ipairs(known) do
    present[name] = true
  end
  for _, name in ipairs(names) do
    if present[name] then return names end
  end
  for _, name in ipairs(known) do
    table.insert(names, name)
  end
  return names
end


-- Return 'x.y' when Nmap reported a two-part series without update, such
-- as 5.5. Any other version shape yields nil.
local function series_prefix(info)
  if info.empty or info.range then return nil end
  local ver = info.ver
  if type(ver) ~= 'string' or not ver:match('^%d+%.%d+$') then
    return nil
  end
  if not empty(info.vup) and info.vup ~= '*' then return nil end
  return ver
end


-- True when the database has rows 'series.%' for the product.
local function series_has_children(vendors, product, series)
  local cur = registry.conn:execute(fmtn(query('series_children'),
    { v = vendors, p = product, s = series }))
  local found = cur:fetch()
  cur:close()
  return tonumber(found) == 1
end


-- Add CVEs from a series expansion that are not already in vulns.
local function merge_series(found, vulns)
  for id, rec in pairs(found) do
    if vulns[id] == nil then
      rec.series_expanded = true
      rec.reasons = { 'series_expanded' }
      vulns[id] = rec
    end
  end
end


-- Return true when the database has the conditions table. Checked once.
local function has_conditions()
  if registry.has_conditions == nil then
    local cur = registry.conn:execute(
      "SELECT name FROM sqlite_master "
      .. "WHERE type = 'table' AND name = 'conditions'")
    registry.has_conditions = cur:fetch() ~= nil
    cur:close()
    if not registry.has_conditions then
      log('[!] Database without conditions table; platform checks skipped.')
    end
  end
  return registry.has_conditions
end


local PLATFORM_RANK = { ok = 4, family = 3, unknown = 2, bad = 1 }

-- Compare one OS platform row with the host context.
-- Return 'ok', 'family', 'unknown' or 'bad'.
local function os_platform_status(row, os_ctx)
  local family = registry.platform_families[row.vendor]
  if family == nil or os_ctx.family == nil then return 'unknown' end
  if family ~= os_ctx.family then return 'bad' end
  if row.vendor == 'linux' then return 'ok' end
  if os_ctx.distro == nil then return 'family' end
  local distro_vendor = os_ctx.distro
  if os_ctx.distro == 'ubuntu' then distro_vendor = 'canonical' end
  if row.vendor == distro_vendor then return 'ok' end
  return 'bad'
end


-- Return the best status, family and vendor of one AND configuration.
-- A configuration without OS platform rows is a component requirement.
local function config_status(rows, os_ctx)
  local best, family, vendor = nil, nil, nil
  for _, row in ipairs(rows) do
    if row.part == 'o' then
      local status = os_platform_status(row, os_ctx)
      family = family or registry.platform_families[row.vendor]
      vendor = vendor or row.vendor
      if best == nil or PLATFORM_RANK[status] > PLATFORM_RANK[best] then
        best = status
      end
    end
  end
  if best == nil then return 'component', nil, nil end
  return best, family, vendor
end


-- Return the platform reason for the configuration rows of one CVE.
-- Any compatible configuration clears the reason.
local function evaluate_platform(rows, os_ctx)
  if #rows == 0 then return nil end
  local configs, order = {}, {}
  for _, row in ipairs(rows) do
    if configs[row.config_idx] == nil then
      configs[row.config_idx] = {}
      table.insert(order, row.config_idx)
    end
    table.insert(configs[row.config_idx], row)
  end
  table.sort(order)
  local all_bad, needs_platform, has_component = true, false, false
  local first_family, first_vendor = nil, nil
  for _, idx in ipairs(order) do
    local status, family, vendor = config_status(configs[idx], os_ctx)
    if status == 'ok' then return nil end
    if status ~= 'bad' then all_bad = false end
    if status == 'unknown' or status == 'family' then
      needs_platform = true
    end
    if status == 'component' then has_component = true end
    if first_family == nil then
      first_family, first_vendor = family, vendor
    end
  end
  if all_bad then
    -- Same family but wrong distro: name the required vendor.
    if first_family == os_ctx.family then
      return 'platform_mismatch:' .. first_vendor
    end
    return 'platform_mismatch:' .. first_family
  end
  if needs_platform then return 'requires_platform' end
  if has_component then return 'requires_component' end
  return nil
end


-- Append the platform reasons of the CVEs in vulns to rec.reasons.
-- No CVE is removed; the visible output does not change.
local function add_platform_reasons(vulns, vendors, product, os_ctx)
  local rows_by_cve = {}
  if has_conditions() then
    local cur = registry.conn:execute(fmtn(query('platform_conditions'),
      { v = vendors, p = product }))
    local cve, config_idx, part, vendor, name = cur:fetch()
    while cve do
      rows_by_cve[cve] = rows_by_cve[cve] or {}
      table.insert(rows_by_cve[cve], {
        config_idx = config_idx,
        part = part,
        vendor = vendor,
        product = name,
      })
      cve, config_idx, part, vendor, name = cur:fetch()
    end
    cur:close()
  end
  for id, rec in pairs(vulns) do
    local reason = evaluate_platform(rows_by_cve[id] or {}, os_ctx)
    rec.reasons = rec.reasons or {}
    if reason then table.insert(rec.reasons, reason) end
  end
end


-- Confidence level of each reason. Platform mismatches are low.
local REASON_LEVEL = {
  exact_version = 'high',
  range_contains = 'high',
  range_overlap = 'medium',
  series_expanded = 'medium',
  update_unknown = 'medium',
  requires_platform = 'medium',
  requires_component = 'medium',
  nvd_unbounded = 'low',
  observed_range = 'low',
}

local LEVEL_RANK = { low = 1, medium = 2, high = 3 }

local CONF_LABEL = { high = 'HIGH', medium = 'MED', low = 'LOW' }

local WARNING_TEXT = {
  distro_backport = 'CVEs pueden estar parcheadas por backport',
}

-- Order rows by confidence first, then by CVSSv3 and CVSSv2.
local function confidence_comparator(a, b)
  if a[6] ~= b[6] then return LEVEL_RANK[a[6]] > LEVEL_RANK[b[6]] end
  return cvss_comparator(a, b)
end


-- Return the level of one reason. Unknown reasons count as low.
local function reason_level(reason)
  if reason:find('^platform_mismatch:') then return 'low' end
  return REASON_LEVEL[reason] or 'low'
end


-- Return the lowest level among the reasons. No reasons means high.
local function confidence_of(reasons)
  local level = 'high'
  for _, reason in ipairs(reasons) do
    local current = reason_level(reason)
    if LEVEL_RANK[current] < LEVEL_RANK[level] then level = current end
  end
  return level
end


-- Set rec.confidence on every CVE and count the levels.
local function score_vulns(vulns)
  local summary = { high = 0, medium = 0, low = 0 }
  for _, rec in pairs(vulns) do
    rec.confidence = confidence_of(rec.reasons)
    summary[rec.confidence] = summary[rec.confidence] + 1
  end
  return summary
end


-- True when a range spans different major.minor series (3.X - 4.X).
local function spans_series(from, to)
  local major_from, minor_from = (from or ''):match('^(%d+)%.?(%d*)')
  local major_to, minor_to = (to or ''):match('^(%d+)%.?(%d*)')
  return major_from ~= major_to or minor_from ~= minor_to
end

-- Add one reason to every CVE of a scan, such as observed_range.
local function add_reason(vulns, reason)
  for _, rec in pairs(vulns) do
    table.insert(rec.reasons, reason)
  end
end


-- Return the CVE count, the output lines, and the meta table with the
-- confidence summary and the service warnings.
local function vulnerabilities(host, port, cpe, vendor, product, info, ctx)
  local vendors = vendor_scope(vendor, product)
  local qrym = fmtn(query('multiaffected'), { v = vendors, p = product })
  local qry = fmtn(query('affected'), { v = vendors, p = product })
  local from = info.ver
  local to = info.ver
  local multi_from = from
  local multi_to = to
  local upd = info.vup or '*'

  if not info.empty then
    if info.range then
      from = info.from:gsub('[xX]', '0')
      to = info.to:gsub('[xX]', '9999999999')
      multi_from = from
      multi_to = to
    elseif not empty(upd) and upd ~= '*' and upd ~= '-' then
      multi_from = info.ver .. upd
      multi_to = multi_from
    end
  else
    -- Given that we assumed '*' as version and vupdate when empty,
    -- we can't search vulnerabilities for specific versions
    qrym = fmtn(query('multiaffected_empty'), { v = vendors, p = product })
  end

  -- Search vulnerabilities affecting multiple versions (this one included)
  local cur = registry.conn:execute(qrym)
  local vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb, metasploit = cur:fetch()
  local tmp_vulns = {}
  local idx = 1
  while vuln do
    tmp_vulns[idx] = {
      id = vuln,
      CVSSV2 = cvssv2,
      CVSSV3 = cvssv3,
      StartInc = st_in,
      StartExc = st_ex,
      EndInc = en_in,
      EndExc = en_ex,
      ExploitDB = exploitdb,
      Metasploit = metasploit
    }
    idx = idx + 1
    vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb, metasploit = cur:fetch()
  end
  cur:close()

  local series = series_prefix(info)
  local expand = series ~= nil and series_has_children(vendors, product, series)

  local vulns = {}
  scoped_multi_versions(tmp_vulns, multi_from, multi_to, vulns, info.empty)
  if expand then
    local found = {}
    scoped_multi_versions(tmp_vulns, series .. '.0',
      series .. '.9999999999', found, false)
    merge_series(found, vulns)
  end

  if not info.empty then
    tmp_vulns = {}
    -- Search vulnerabilities affecting specific version
    cur = registry.conn:execute(qry)
    local pr_v, pr_vu
    vuln, cvssv2, cvssv3, pr_v, pr_vu, exploitdb, metasploit = cur:fetch()
    idx = 1
    while vuln do
      tmp_vulns[idx] = {
        id = vuln,
        CVSSV2 = cvssv2,
        CVSSV3 = cvssv3,
        version = pr_v,
        version_update = pr_vu,
        ExploitDB = exploitdb,
        Metasploit = metasploit
      }
      idx = idx + 1
      vuln, cvssv2, cvssv3, pr_v, pr_vu, exploitdb, metasploit = cur:fetch()
    end
    scoped_versions(tmp_vulns, from, to, upd, vulns)
    if expand then
      local found = {}
      scoped_versions(tmp_vulns, series .. '.0',
        series .. '.9999999999', '*', found)
      merge_series(found, vulns)
    end
    cur:close()
  end

  if info.range and spans_series(info.from, info.to) then
    add_reason(vulns, 'observed_range')
  end
  add_platform_reasons(vulns, vendors, product, ctx and ctx.os or {})
  local meta = {
    summary = score_vulns(vulns),
    warnings = {},
    version_source = ctx and ctx.version_source,
    os_context = ctx and ctx.os or {},
    shown = 0,
  }
  if ctx and ctx.backport then
    table.insert(meta.warnings, 'distro_backport')
  end

  -- Sort CVEs by confidence, then by CVSSv3 and CVSSv2
  local sorted = {}
  for key, value in pairs(vulns) do
    table.insert(sorted, { key,
      value.CVSSV2, value.CVSSV3,
      value.ExploitDB,
      value.Metasploit,
      value.confidence })
  end
  table.sort(sorted, confidence_comparator)
  log("[+] cves: %d", #sorted)

  -- Insert total vulnerabilities found
  local output = {}
  table.insert(output, #sorted)

  -- Pretty print the output
  local cnt = 0
  if #sorted > 0 then
    local port_proto = fmt('%s/%s', port.number, port.protocol)
    if registry.json_out[host.ip]['ports'][port_proto] == nil then
      registry.json_out[host.ip]['ports'][port_proto] = { ['services'] = {} }
    end
    local v, vu = correct_version(info)
    table.insert(
      registry.json_out[host.ip]['ports'][port_proto]['services'],
      {
        name = port.service,
        cpe = cpe,
        vendor = vendor,
        product = product,
        version = v,
        vupdate = vu,
        version_source = meta.version_source,
        os_context = meta.os_context,
        warnings = meta.warnings,
        summary = meta.summary,
        vulnerabilities = {
          ['total'] = 0,
          ['info'] = 'scan',
          ['cves'] = {}
        }
      }
    )
  end
  for _, value in ipairs(sorted) do
    local show = LEVEL_RANK[value[6]] >= LEVEL_RANK[minconf_arg]
    dump_exploit(host, port, value[1], vulns[value[1]], show)
    if show then
      if cnt < maxcve_arg then
        table.insert(output,
          fmt(
            "\t%-20s\t%-6s\t%-5s\t%-5s\t%-10s\t%-10s",
            value[1], CONF_LABEL[value[6]],
            value[2], value[3] or "-",
            value[4] == 1 and "Yes" or "No",
            value[5] == 1 and "Yes" or "No"
          )
        )
      end
      cnt = cnt + 1
    end
  end
  meta.shown = cnt
  log_separator()
  return output, meta
end


local OS_NAME_FAMILIES = {
  linux = 'linux',
  windows = 'windows',
  ['mac os x'] = 'macos',
  macos = 'macos',
  freebsd = 'bsd',
  openbsd = 'bsd',
  netbsd = 'bsd',
  solaris = 'solaris',
}

local DISTRO_NAMES = {
  { 'ubuntu', 'ubuntu' },
  { 'debian', 'debian' },
  { 'red hat', 'redhat' },
  { 'centos', 'centos' },
  { 'suse', 'suse' },
}

local BACKPORT_PATTERNS = {
  'ubuntu%d', 'debian', '%(ubuntu%)', '%(debian%)',
  '%f[%a]el%d', '%f[%a]deb%d', 'red hat',
}

local function version_text(port)
  local info = port.version or {}
  return string.lower(
    (info.version or '') .. ' ' .. (info.extrainfo or '')
  )
end

local function name_family(name)
  if type(name) ~= 'string' then return nil end
  return OS_NAME_FAMILIES[string.lower(name)]
end

local function vendor_family(vendor)
  if type(vendor) ~= 'string' then return nil end
  return registry.platform_families[string.lower(vendor)]
end

local function family_from_cpe(cpe)
  local _, _, kind, vendor = split_cpe(cpe)
  if kind ~= 'o' then return nil end
  return vendor_family(vendor)
end

local function cpes_family(cpes)
  for _, cpe in ipairs(cpes or {}) do
    local family = family_from_cpe(cpe)
    if family then return family end
  end
  return nil
end

local function first_host_os_family(host)
  local matches = host.os
  if type(matches) ~= 'table' or type(matches[1]) ~= 'table' then
    return nil
  end
  local first = matches[1]
  local family = cpes_family(first.cpe)
  for _, class in ipairs(first.classes or first.osclass or {}) do
    family = family or cpes_family(class.cpe)
      or name_family(class.osfamily) or vendor_family(class.vendor)
  end
  return family
end

-- Cache the host.os family per IP; false marks a negative result.
local function host_os_family(host)
  if registry.host_os[host.ip] == nil then
    local ok, family = pcall(first_host_os_family, host)
    registry.host_os[host.ip] = ok and family or false
  end
  return registry.host_os[host.ip] or nil
end

local function text_os(port)
  local text = version_text(port)
  for _, entry in ipairs(DISTRO_NAMES) do
    if text:find(entry[1], 1, true) then return 'linux', entry[2] end
  end
  if text:find('windows', 1, true) then return 'windows', nil end
  return nil, nil
end

local function os_context(host, port)
  local info = port.version or {}
  local family, source = cpes_family(info.cpe), 'cpe'
  if family == nil then
    family, source = name_family(info.ostype), 'ostype'
  end
  if family == nil then
    family, source = host_os_family(host), 'host_os'
  end
  local text_family, distro = text_os(port)
  if family == nil then
    family, source = text_family, 'extrainfo'
  end
  if family == nil then return {} end
  return { family = family, distro = distro, source = source }
end

local function distro_backport(port)
  local text = version_text(port)
  for _, pattern in ipairs(BACKPORT_PATTERNS) do
    if text:find(pattern) then return true end
  end
  return false
end


-- Key of the per-service context that changes the output of a scan.
local function context_key(ctx)
  local os_ctx = ctx.os or {}
  return fmt('%s|%s|%s|%s|%s', tostring(ctx.version_source),
    tostring(os_ctx.family), tostring(os_ctx.distro),
    tostring(os_ctx.source), tostring(ctx.backport))
end


-- Prepend the service header lines to the CVE rows of one service.
local function service_lines(vendor, product, v, vu, nvulns, meta, rows)
  local lines = {
    fmt("vendor: %s", vendor),
    fmt("product: %s", product),
    fmt("version: %s", v),
    fmt("vupdate: %s", vu),
    fmt("version_source: %s", meta.version_source or '-'),
  }
  for _, warning in ipairs(meta.warnings) do
    table.insert(lines, fmt("warning: %s", WARNING_TEXT[warning] or warning))
  end
  local total = ''
  if meta.shown < nvulns then total = fmt(' (total %d)', nvulns) end
  table.insert(lines, fmt("cves: %d%s", meta.shown, total))
  table.insert(lines, fmt("\t%-20s\t%-6s\t%-5s\t%-5s\t%-10s\t%-10s",
    "CVE ID", "Conf", "CVSSv2", "CVSSv3", "ExploitDB", "Metasploit"))
  for _, row in ipairs(rows) do table.insert(lines, row) end
  return lines
end


-- ctx: OS and distro context from os_context and distro_backport.
local function analysis(host, port, matches, ctx)
  local vulns = {}
  local logged = {}
  for origin, data in pairs(matches['data']) do
    for cpe, versions in pairs(data) do
      for version, _ in pairs(versions) do
        stdnse.verbose(2, fmt("cpe => %s | version => %s", cpe, version))
        local vendor, product, info, source = cpe_parser(cpe, version)
        local version_source = source
        if origin == 'smb' or origin == 'http' then
          version_source = origin
        end
        if ((service_arg == 'all' and version_arg == 'all')
              or (service_arg ~= 'all' and version_arg ~= 'all'
                and product == service_arg and version == version_arg)
              or (service_arg ~= 'all' and version_arg == 'all'
                and product == service_arg)
              or (service_arg == 'all' and version_arg ~= 'all' and version == version_arg)) then
          stdnse.verbose(2, fmt("product => %s | version => %s", product, version))
          if info ~= nil then
            log_info(host, port, cpe, vendor, product, info)
            local v, vu = correct_version(info)
            local tmp_vulns = nil
            local vctx = {
              os = ctx.os,
              backport = ctx.backport,
              version_source = version_source,
            }
            local cache_key = fmt('%s|%s|%s|%s|%s', vendor, product, v, vu,
              context_key(vctx))
            if not registry.cache[cache_key] then
              local meta
              tmp_vulns, meta = vulnerabilities(host, port, cpe, vendor,
                product, info, vctx)
              local nvulns = table.remove(tmp_vulns, 1)
              if nvulns > 0 then
                local serv_fmt = fmt('%s/%s', port.number, port.protocol)
                local t_serv = #registry.json_out[host.ip]['ports'][serv_fmt]['services']
                registry.json_out[host.ip]['ports'][serv_fmt]['services'][t_serv]['vulnerabilities']['total'] = nvulns
                tmp_vulns = service_lines(vendor, product, v, vu, nvulns,
                  meta, tmp_vulns)
                stdnse.verbose(2, "Caching " .. product .. "|" ..
                  v .. "|" .. vu .. " vulnerabilities.")
                registry.cache[cache_key] = { nvulns, tmp_vulns, meta }
              end
            else
              log("[+] cves: cached")
              local cache = registry.cache[cache_key]
              if cache[1] > 0 then
                local port_proto = fmt('%s/%s', port.number, port.protocol)
                if registry.json_out[host.ip]['ports'][port_proto] == nil then
                  registry.json_out[host.ip]['ports'][port_proto] = { ['services'] = {} }
                end
                table.insert(
                  registry.json_out[host.ip]['ports'][port_proto]['services'],
                  {
                    name = port.service,
                    cpe = cpe,
                    vendor = vendor,
                    product = product,
                    version = v,
                    vupdate = vu,
                    version_source = cache[3].version_source,
                    os_context = cache[3].os_context,
                    warnings = cache[3].warnings,
                    summary = cache[3].summary,
                    vulnerabilities = {
                      ['total'] = cache[1],
                      ['info'] = 'cache'
                    }
                  }
                )
              end
              log_separator()
              stdnse.verbose(2, "Using cached " .. product .. "|" ..
                v .. "|" .. vu .. " vulnerabilities.")
              tmp_vulns = cache[2]
            end
            local log_key = fmt("%s|%s|%s|%s", vendor, product, v, vu)
            if (tmp_vulns ~= nil and #tmp_vulns > 0
                  and logged[log_key] == nil) then
              logged[log_key] = 1
              for _, value in pairs(tmp_vulns) do
                table.insert(vulns, value)
              end
              table.insert(vulns, "")
            end
          end
        end
      end
    end
  end
  return vulns
end


prerule = function()
  local req = required_files()
  if req ~= "" then
    stdnse.verbose(1, req)
    registry.status = false
  end
  return registry.status
end


hostrule = function(_)
  return registry.status
end


portrule = function(_, port)
  return registry.status and
      port.service ~= 'tcpwrapped' and
      port.service ~= 'unknown'
end


postrule = function()
  return registry.status
end


preaction = function()
  registry.env = sql.sqlite3()
  registry.conn = registry.env:connect(db_arg)
  registry.logger = io.open(log_arg, 'a')
  registry.time = datetime.format_timestamp(os.time(), 0)
  registry.cache = {}
  registry.json_out = {}
  timestamp()
  if not minconf_valid then
    log("[!] minconf '%s' is invalid, using low", minconf_raw)
  end
end


hostaction = function(host)
  if registry.json_out[host.ip] == nil then
    registry.json_out[host.ip] = {
      ['timestamp'] = registry.time,
      ['ports'] = {}
    }
  end
end


local SMB_PORTS = { [139] = true, [445] = true }
local SMB_SERVICES = { ['microsoft-ds'] = true, ['netbios-ssn'] = true }

--- Return the exact Samba version reported by the SMB service.
-- The result is cached per host so each port reuses the same probe.
local function smb_version(host, port)
  if smb_arg ~= '1' or not smb_ok then return nil end
  if not (SMB_PORTS[port.number] or SMB_SERVICES[port.service]) then
    return nil
  end
  if registry.smb[host.ip] == nil then
    local version = false
    local ok, status, info = pcall(smb.get_os, host)
    if not ok then
      stdnse.verbose(2, fmt("smb probe failed: %s", tostring(status)))
    elseif not status then
      stdnse.verbose(2, fmt("smb probe failed: %s", tostring(info)))
    elseif type(info) == 'table' and type(info.lanmanager) == 'string' then
      version = info.lanmanager:match('^Samba%s+([%d%.]+[%w%.]*)') or false
    end
    registry.smb[host.ip] = version
  end
  return registry.smb[host.ip] or nil
end


--- Add the Nmap CPE of a port, or the SMB version when Samba is detected.
local function add_nmap_matches(host, port, matches)
  local cpe = port.version.cpe[1]
  local detected_version = port.version.version
  if empty(detected_version) then detected_version = '*' end
  local _, _, _, _, product = split_cpe(cpe)
  local smb_ver = nil
  if product == 'samba' then smb_ver = smb_version(host, port) end
  if smb_ver then
    add_cpe_version('cpe:/a:samba:samba', smb_ver, matches, 'smb')
    return
  end
  add_cpe_version(cpe, detected_version, matches, 'nmap')
  add_cpe_aliases(cpe, detected_version, matches, 'nmap')
end


portaction = function(host, port)
  local matches = {
    ['data'] = { ['nmap'] = {}, ['http'] = {}, ['smb'] = {} },
    ['size'] = 0
  }
  local triggered = {}
  if registry.json_out[host.ip] == nil then
    registry.json_out[host.ip] = {
      ['timestamp'] = registry.time,
      ['ports'] = {}
    }
  end
  if port.version ~= nil
      and port.version.cpe ~= nil
      and port.version.cpe[1] ~= nil then
    add_nmap_matches(host, port, matches)
  end
  match_banner(port, matches, triggered)
  if http_arg == '1'
      and (shortport.http(host, port)
        or shortport.ssl(host, port)
        or port.service == 'upnp') then
    http_match(host, port, matches, triggered)
  end
  local vulns
  if matches['size'] ~= 0 then
    local ctx = {
      os = os_context(host, port),
      backport = distro_backport(port),
    }
    vulns = analysis(host, port, matches, ctx)
  end
  if vulns and #vulns > 0 then return vulns end
end


postaction = function()
  local closed, close_err = pcall(registry.conn.close, registry.conn)
  if not closed then
    log("[!] could not close database connection: %s", close_err)
  end
  registry.env:close()
  registry.logger:write("\n")
  registry.logger:close()
  local json_out = io.open(json_arg, 'a')
  json_out:write(json.generate(registry.json_out))
  json_out:write("\n")
  json_out:close()
end


local ActionsTable = {
  prerule = preaction,
  hostrule = hostaction,
  portrule = portaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
