-- SPDX-License-Identifier: GPL-3.0-or-later

-- cvescannerv2 - NSE script.

-- Copyright (C) 2021-2024 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
-- Universidad Carlos III de Madrid.

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
--- Prerequisite: cve.db. Can be generated using database.py or obtained from https://github.com/scmanjarrez/CVEScannerV2DB
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
-- db: Modify the database file location. Default: cve.db
-- maxcve: Limit the number of CVEs printed on screen. Default: 10
-- http: Modify HTTP analysis behaviour. Default: 1 (enabled). Possible values: 0, 1
-- maxredirect: Limit the number of redirections. Default: 1
-- log: Modify the output .log file location. Default: cvescannerv2.log
-- json: Modify the output .json file location. Default: cvescannerv2.json
-- path: Modify the paths file location. Default: extra/http-paths-vulnerscom.json
-- regex: Modify the regex file location. Default: extra/http-regex-vulnerscom.json
-- aliases: Modify the product-aliases file location. Default: extra/product-aliases.json
-- service: Modify the search scope to specific service. Default: all
-- version: Modify the search scope to specific version. Default: all
---

categories = {"safe"}
author = "Sergio Chica"
version = "3.3"

local http = require 'http'
http.USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0'
local json = require 'json'
local nmap = require 'nmap'
local datetime = require 'datetime'
local shortport = require 'shortport'
local sql = require 'luasql.sqlite3'
local stdnse = require 'stdnse'

local db_arg = stdnse.get_script_args('db') or 'cve.db'
local maxcve_arg = tonumber(stdnse.get_script_args('maxcve')) or 10
local http_arg = stdnse.get_script_args('http') or '1'
local maxredirect_arg = tonumber(stdnse.get_script_args('maxredirect')) or 1
local log_arg = stdnse.get_script_args('log') or 'cvescannerv2.log'
local json_arg = stdnse.get_script_args('json') or 'cvescannerv2.json'
-- local word_arg = stdnse.get_script_args('word') or nil
-- local ext_arg = stdnse.get_script_args('ext') or nil
local path_arg = stdnse.get_script_args('path') or 'extra/http-paths-vulnerscom.json'
local regex_arg = stdnse.get_script_args('regex') or 'extra/http-regex-vulnerscom.json'
local aliases_arg = stdnse.get_script_args('aliases') or 'extra/product-aliases.json'
local service_arg = stdnse.get_script_args('service') or 'all'
local version_arg = stdnse.get_script_args('version') or 'all'


if not nmap.registry[SCRIPT_NAME] then
   nmap.registry[SCRIPT_NAME] = {
      conn = nil,
      cache = nil,
      env = nil,
      logger = nil,
      json_out = nil,
      path = nil,
      regex = nil,
      status = true,
      time = nil
   }
end


local registry = nmap.registry[SCRIPT_NAME]


local function empty (str)
   return str == nil or str == ''
end


local function exists (file)
   local f = io.open(file, 'r')
   return f ~= nil and f:close()
end


local function fmt (msg, ...)
   return msg:format(...)
end

-- Implementation of named parameters from RiciLake@lua-users
local function fmtn(msg, tab)
   return msg:gsub(
      '($%b{})',
      function(nparam)
         -- nparam -> ${var} => nparam:sub(3, -2) -> var
         return tab[nparam:sub(3, -2)] or "nil"
      end
   )
end


local function timestamp ()
   registry.logger:write(fmt("## %s\n", registry.time))
   stdnse.verbose(1, fmt("Timestamp: %s", registry.time))
   stdnse.verbose(1, fmt("CVE data source: %s", "nvd.nist.gov"))
   stdnse.verbose(1, fmt("Script version: %s", version))
end


local function correct_version (info)
   if not info.range then
      return info.ver, info.vup
   else
      return info.from .. " - ".. info.to, "*"
   end
end


local function log (msg, ...)
   registry.logger:write(fmt(msg .. "\n", ...))
end


local function log_separator ()
   log(string.rep("-", 49))
end


local function log_info (host, port, cpe, product, info)
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
   log("[+] product: %s", _prod)
   log("[+] version: %s", _ver)
   log("[+] vupdate: %s", _vupd)
end


local function valid_json (arg, ftype)
   local f = io.open(arg, 'r')
   local status, data = json.parse(f:read('*all'))
   if status then
      if ftype == 'path' then
         registry.path = data
      elseif ftype == 'regex' then
        registry.regex = data
      elseif ftype == 'aliases' then
        registry.aliases = data
      end
   end
   f:close()
   return status
end


local function required_files ()
   local ret = ""
   if not exists(db_arg) then
      ret = fmt("Database %s could not be read. " ..
                "Run ./databases.py before running nmap script.",
                db_arg)
   elseif not exists(path_arg) then
      ret = fmt("Paths file %s not found.", path_arg)
   elseif not exists(regex_arg) then
      ret = fmt("Regexes file %s not found.", regex_arg)
   elseif not exists(aliases_arg) then
      ret = fmt("CPE product aliases file %s not found.", aliases_arg)
   elseif not valid_json(path_arg, 'path') then
      ret = fmt("Invalid json %s.", path_arg)
   elseif not valid_json(regex_arg, 'regex') then
      ret = fmt("Invalid json %s.", regex_arg)
   elseif not valid_json(aliases_arg, 'aliases') then
      ret = fmt("Invalid json %s.", aliases_arg)
   end
   return ret
end


local function add_cpe_version(cpe, version, matches, location)
   if version:sub(-1) == '.' then  -- strip dot at the end of version
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


local function add_cpe_aliases(cpe, version, matches, location)
   local parts = {}
   for part in string.gmatch(cpe, "([^:]+)") do
      table.insert(parts, part)
   end
   local product = parts[4]
   -- Product aliases
   if registry.aliases[product] then
      for _, alias in pairs(registry.aliases[product]) do
         parts[4] = alias
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


local function regex_match (text, location, matches)
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

local function redirect(_, _)
   -- Taken from https://nmap.org/nsedoc/lib/http.html
   -- https://svn.nmap.org/nmap/nselib/http.lua
   local c = maxredirect_arg
   return function(_)
      if c == 0 then return false end
      c = c - 1
      return true
   end
end

local function http_match (host, port, matches)
   for _, path in pairs(registry.path['path']) do
      for _, ext in pairs(registry.path['extension']) do
         local file = "/" .. path .. ext
         if (path == '' and ext == '') or path ~= '' then
            local resp = http.get(host, port, file,
                                  {
                                     redirect_ok = redirect,
                                     timeout = 90,
                                     bypass_cache = true,
                                     no_cache = true,
                                     no_cache_body = true
                                  }
            )
            if not resp.status then
               stdnse.verbose(2, fmt("Error processing request http://%s:%s%s => %s",
                                     host.ip, port.number, file, resp['status-line']))
            else
               if #resp.rawheader > 0 then
                  for _, header in pairs(resp.rawheader) do
                     regex_match(header, 'header', matches)
                  end
               end
               if resp.rawbody ~= "" then
                  regex_match(resp.rawbody, 'body', matches)
               end
            end
            if path == '' and ext == '' and resp.status then
               local idx = 0
               local lib_path = nil
               local libs = {['size'] = 0}
               while true do
                  _, idx, lib_path = resp.rawbody:find(
                     registry.regex['external']['path_regex'], idx + 1)
                  if lib_path and lib_path:sub(1, 1) == '/' then
                     local lib_resp = http.get(host, port, lib_path,
                                               {
                                                  redirect_ok = redirect,
                                                  timeout = 90,
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
                           local k_stripped = (k:gsub('.js', '')):lower()
                           if (name:lower()):find(k_stripped) then
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


local function version_parser (product, version)
   if version then
      -- remove Nmap comment of version
      version = version:gsub('for_windows_', '')
   end

   -- if Nmap could not detect version, assume all versions and vupdates possible
   if empty(version) then
      return product, {ver = '*', vup = '*',
                       from = nil, to = nil,
                       empty = true, range = false}
   end

   -- if version matches patterns: 3.x - 4.x | 3.3.x - 3.4.x ...
   local p1, p2 = version:match('([^-]*)%s+-%s+([^-]*)')
   if not empty(p1) and not empty(p2) then
      local f1, f2 = p1:match('([^%a]*)(.*)')
      local t1, t2 = p2:match('([^%a]*)(.*)')
      return product, {ver = nil, vup = nil,
                       from = f1 .. f2,
                       to = t1 .. t2,
                       empty = false, range = true}
   end

   -- if version matches patterns: 4.3 | 4.3p1 | 4.3.1sp1 ...
   p1, p2 = version:match('([%d.]*)([^-]*)')
   if not empty(p1) then
      if empty(p2) then
         p2 = '*'
      end
      return product, {ver = p1, vup = p2,
                       from = nil, to = nil,
                       empty = false, range = false}
   end
end


local function cpe_parser (cpe, version)
   local info = {}
   for data in (cpe .. ':'):gmatch('([^:]*):') do
      table.insert(info, data)
   end

   -- [1] = cpe, [2] = /a or /h or /o, [3] = vendor, [4] = product, [5] = version
   if #info == 4 then
      table.insert(info, version)
   end

   return version_parser(info[4], info[5])
end


local function query (qtype)
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
             (SELECT product_id FROM products WHERE product = '${p}' AND version = '*')
             ]]
   elseif qtype == 'multiaffected_empty' then
      return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id IN
             (SELECT product_id FROM products WHERE product = '${p}' AND version = '*' and version_update = '*')
             AND versionStartIncluding IS NULL AND versionStartExcluding IS NULL
             AND versionEndIncluding IS NULL AND versionEndExcluding IS NULL
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
             WHERE products.product = '${p}'
             ]]
   end
end


local function dump_exploit (host, port, vuln)
   local _ip = host.ip
   local _port = fmt('%s/%s', port.number, port.protocol)
   -- Dump the CVE score
   local cur = registry.conn:execute(
      fmt(query('cve_score'), vuln)
   )
   local cvssv2, cvssv3 = cur:fetch()
   log("[-] \tid: %-18s\tcvss_v2: %-5s\tcvss_v3: %-5s", vuln, cvssv2, cvssv3 or "-")
   local t_serv = #registry.json_out[_ip]['ports'][_port]['services']
   registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln] = {
      ['cvssv2'] = cvssv2,
      ['cvssv3'] = cvssv3 or "-"
   }

   -- Dump exploits from Exploit-DB
   cur = registry.conn:execute(
      fmt(query('exploit_info'), vuln)
   )
   local exploit, name = cur:fetch()
   if exploit then
      log("[!] \t\tExploitDB:")
      registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]['exploitdb'] = {}
      local exp_list = registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]['exploitdb']
      while exploit do
         log("[#] \t\t\tname: %s", name)
         log("[#] \t\t\tid: %s", exploit)
         log("[#] \t\t\turl: https://www.exploit-db.com/exploits/%s", exploit)
         exp_list[#exp_list + 1] = {
            ['name'] = name,
            ['id'] = exploit,
            ['url'] = fmt('https://www.exploit-db.com/exploits/%s', exploit)
         }
         exploit, name = cur:fetch()
      end
   end

   -- Dump exploits from Metasploit
   cur = registry.conn:execute(
      fmt(query('metasploit_info'), vuln)
   )
   name = cur:fetch()
   if name then
      log("[!] \t\tMetasploit:")
      registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]['metasploit'] = {}
      local meta_list = registry.json_out[_ip]['ports'][_port]['services'][t_serv]['vulnerabilities']['cves'][vuln]['metasploit']
      while name do
         log("[#] \t\t\tname: %s", name)
         meta_list[#meta_list + 1] = {['name'] = name}
         name = cur:fetch()
      end
   end
end


local function cvss_comparator(a, b)
   if a[3] ~= nil and b[3] ~= nil then
      return a[3] > b[3]
   elseif a[3] ~= nil and b[2] ~= nil then
      return a[3] > b[2]
   elseif a[2] ~= nil and b[3] ~= nil then
      return a[2] > b[3]
   elseif a[2] ~= nil and b[2] ~= nil then
      return a[2] > b[2]
   else
      return false
   end
end


local function split_version(str)
   local parts = {}
   for part in string.gmatch(str, "([^.]+)") do
      table.insert(parts, part)
   end
   return parts
end


local function remove_alpha(str)
    local numeric, alpha = string.match(str, "([%d%.]+)(%a*)")
    return numeric, alpha
end


local function compare_version(version1, version2)
   version1, _ = remove_alpha(version1)
   version2, _ = remove_alpha(version2)
   local parts1 = split_version(version1)
   local parts2 = split_version(version2)
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
   return 0
end


local function default_version(version, default)
   if version == nil or version == '-' then
      return default
   else
      return version
   end
end


local function scoped_multi_versions(all_versions, from, to, result)
   local vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb, metasploit
   for _, v in pairs(all_versions) do
      st_in = default_version(v.StartInc, '0')
      st_ex = default_version(v.StartExc, '0')
      en_in = default_version(v.EndInc, '9999999999')
      en_ex = default_version(v.EndExc, '9999999999')
      if string.find(from, '%.') and string.find(to, '%.9999999999') then
         -- range search
         if ((compare_version(st_in, from) >= 0 or compare_version(st_ex, from) > 0)
             and (compare_version(en_in, to) <= 0 or compare_version(en_ex, to) < 0)) then
            vuln = v.id
            cvssv2 = v.CVSSV2
            cvssv3 = v.CVSSV3
            exploitdb = v.ExploitDB
            metasploit = v.Metasploit
            if result[vuln] == nil then
               result[vuln] = {
                  ['CVSSV2'] = cvssv2, ['CVSSV3'] = cvssv3,
                  ['ExploitDB'] = exploitdb,
                  ['Metasploit'] = metasploit
               }
            end
         end
      else
         if compare_version(from, st_in) >= 0 and compare_version(from, st_ex) > 0
            and compare_version(to, en_in) <= 0 and compare_version(to, en_ex) < 0 then
            vuln = v.id
            cvssv2 = v.CVSSV2
            cvssv3 = v.CVSSV3
            exploitdb = v.ExploitDB
            metasploit = v.Metasploit
            if result[vuln] == nil then
               result[vuln] = {
                  ['CVSSV2'] = cvssv2, ['CVSSV3'] = cvssv3,
                  ['ExploitDB'] = exploitdb,
                  ['Metasploit'] = metasploit
               }
            end
         end
      end
   end
end


local function scoped_versions(all_versions, from, to, upd, result)
   local vuln, cvssv2, cvssv3, pr_v, pr_vu, exploitdb, metasploit

   for _, v in pairs(all_versions) do
      pr_v = default_version(v.version, '0')
      pr_vu = default_version(v.version_update, '*')
      if from ~= to then
         if ((compare_version(pr_v, from) >= 0
              or compare_version(pr_v .. pr_vu, from) >= 0)
            and (compare_version(pr_v, to) <= 0
                 or compare_version(pr_v .. pr_vu, to) <= 0)) then
            vuln = v.id
            cvssv2 = v.CVSSV2
            cvssv3 = v.CVSSV3
            exploitdb = v.ExploitDB
            metasploit = v.Metasploit
            if result[vuln] == nil then
               result[vuln] = {
                  ['CVSSV2'] = cvssv2, ['CVSSV3'] = cvssv3,
                  ['ExploitDB'] = exploitdb,
                  ['Metasploit'] = metasploit
               }
            end
         end
      else
         if ((compare_version(pr_v, from) == 0 and (pr_vu == upd or upd == '*'))
             or (compare_version(pr_v .. pr_vu, from) == 0 and (pr_vu == '*' or upd == '*'))) then
            vuln = v.id
            cvssv2 = v.CVSSV2
            cvssv3 = v.CVSSV3
            exploitdb = v.ExploitDB
            metasploit = v.Metasploit
            if result[vuln] == nil then
               result[vuln] = {
                  ['CVSSV2'] = cvssv2, ['CVSSV3'] = cvssv3,
                  ['ExploitDB'] = exploitdb,
                  ['Metasploit'] = metasploit
               }
            end
         end
      end
   end
end



local function vulnerabilities (host, port, cpe, product, info)
   local qrym = fmtn(query('multiaffected'), {p = product})
   local qry = fmtn(query('affected'), {p = product})
   local from = info.ver
   local to = info.ver
   local upd = info.vup

   if not info.empty then
      if info.range then
         from = info.from:gsub('[xX]', '0')
         to = info.to:gsub('[xX]', '9999999999')
      end
   else
      -- Given that we assumed '*' as version and vupdate when empty,
      -- we can't search vulnerabilities for specific versions
      qrym = fmtn(query('multiaffected_empty'), {p = product})
   end

   -- Search vulnerabilities affecting multiple versions (this one included)
   local cur = registry.conn:execute(qrym)
   local vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb, metasploit = cur:fetch()
   local tmp_vulns = {}
   local idx = 1
   while vuln do
      tmp_vulns[idx] = {
         id = vuln,
         CVSSV2 = cvssv2, CVSSV3 = cvssv3,
         StartInc = st_in, StartExc = st_ex,
         EndInc = en_in, EndExc = en_ex,
         ExploitDB = exploitdb,
         Metasploit = metasploit
      }
      idx = idx + 1
      vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb, metasploit = cur:fetch()
   end

   local vulns = {}
   scoped_multi_versions(tmp_vulns, from, to, vulns)

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
            CVSSV2 = cvssv2, CVSSV3 = cvssv3,
            version = pr_v, version_update = pr_vu,
            ExploitDB = exploitdb,
            Metasploit = metasploit
         }
         idx = idx + 1
         vuln, cvssv2, cvssv3, pr_v, pr_vu, exploitdb, metasploit = cur:fetch()
      end
   end

   scoped_versions(tmp_vulns, from, to, upd, vulns)

   -- Sort CVEs by CVSSv3 and CVSSv2
   local sorted = {}
   for key, value in pairs(vulns) do
      table.insert(sorted, {key,
                            value.CVSSV2, value.CVSSV3,
                            value.ExploitDB,
                            value.Metasploit})
   end
   table.sort(sorted, cvss_comparator)
   log("[+] cves: %d", #sorted)

   -- Insert total vulnerabilities found
   local output = {}
   table.insert(output, #sorted)

   -- Pretty print the output
   local cnt = 0
   if #sorted > 0 then
      local port_proto = fmt('%s/%s', port.number, port.protocol)
      if registry.json_out[host.ip]['ports'][port_proto] == nil then
         registry.json_out[host.ip]['ports'][port_proto] = {['services'] = {}}
      end
      local v, vu = correct_version(info)
      table.insert(
         registry.json_out[host.ip]['ports'][port_proto]['services'],
         {
            name = port.service,
            cpe = cpe,
            product = product,
            version = v,
            vupdate = vu,
            vulnerabilities = {
               ['total'] = 0,
               ['info'] = 'scan',
               ['cves'] = {}
            }
         }
      )
   end
   for _, value in pairs(sorted) do
      dump_exploit(host, port, value[1])
      if cnt < maxcve_arg then
         table.insert(output,
                      fmt(
                         "\t%-20s\t%-5s\t%-5s\t%-10s\t%-10s",
                         value[1],
                         value[2], value[3] or "-",
                         value[4] == 1 and "Yes" or "No",
                         value[5] == 1 and "Yes" or "No"
                      )
         )
      end
      cnt = cnt + 1
   end
   log_separator()
   cur:close()
   return output
end


local function analysis (host, port, matches)
   local vulns = {}
   local logged = {}
   for _, data in pairs(matches['data']) do
      for cpe, versions in pairs(data) do
         for version, _ in pairs(versions) do
            stdnse.verbose(2, fmt("cpe => %s | version => %s", cpe, version))
            local product, info = cpe_parser(cpe, version)
            if ((service_arg == 'all' and version_arg == 'all')
               or (service_arg ~= 'all' and version_arg ~= 'all'
                   and product == service_arg and version == version_arg)
               or (service_arg ~= 'all' and version_arg == 'all'
                   and product == service_arg)
               or (service_arg == 'all' and version_arg ~= 'all' and version == version_arg)) then
               stdnse.verbose(2, fmt("product => %s | version => %s", product, version))
               if info ~= nil then
                  log_info(host, port, cpe, product, info)
                  local v, vu = correct_version(info)
                  local tmp_vulns = nil
                  if not registry.cache[fmt('%s|%s|%s', product, v, vu)] then
                     tmp_vulns = vulnerabilities(host, port, cpe, product, info)
                     local nvulns = table.remove(tmp_vulns, 1)
                     if nvulns > 0 then
                        table.insert(tmp_vulns, 1, fmt("product: %s", product))
                        table.insert(tmp_vulns, 2, fmt("version: %s", v))
                        table.insert(tmp_vulns, 3, fmt("vupdate: %s", vu))
                        table.insert(tmp_vulns, 4, fmt("cves: %d", nvulns))
                        local serv_fmt = fmt('%s/%s', port.number, port.protocol)
                        local t_serv = #registry.json_out[host.ip]['ports'][serv_fmt]['services']
                        registry.json_out[host.ip]['ports'][serv_fmt]['services'][t_serv]['vulnerabilities']['total'] = nvulns
                        table.insert(tmp_vulns, 5,
                           fmt(
                              "\t%-20s\t%-5s\t%-5s\t%-10s\t%-10s",
                              "CVE ID", "CVSSv2", "CVSSv3", "ExploitDB", "Metasploit"
                          )
                        )
                        stdnse.verbose(2, "Caching " .. product .. "|" ..
                           v .. "|" .. vu .. " vulnerabilities.")
                        registry.cache[fmt('%s|%s|%s', product, v, vu)] = { nvulns, tmp_vulns }
                     end
                  else
                     log("[+] cves: cached")
                     local cache = registry.cache[fmt('%s|%s|%s', product, v, vu)]
                     if cache[1] > 0 then
                        local port_proto = fmt('%s/%s', port.number, port.protocol)
                        if registry.json_out[host.ip]['ports'][port_proto] == nil then
                           registry.json_out[host.ip]['ports'][port_proto] = {['services'] = {}}
                        end
                        table.insert(
                           registry.json_out[host.ip]['ports'][port_proto]['services'],
                           {
                              name = port.service,
                              cpe = cpe,
                              product = product,
                              version = v,
                              vupdate = vu,
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
                  if (tmp_vulns ~= nil and #tmp_vulns > 0
                      and logged[fmt("%s|%s", product, version)] == nil) then
                     logged[fmt("%s|%s", product, version)] = 1
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


prerule = function ()
   local req = required_files()
   if req ~= "" then
      stdnse.verbose(1, req)
      registry.status = false
   end
   return registry.status
end


hostrule = function (_)
   return registry.status
end


portrule = function (_, port)
   return registry.status and
      port.service ~= 'tcpwrapped' and
      port.service ~= 'unknown'
end


postrule = function ()
   return registry.status
end


preaction = function ()
   registry.env = sql.sqlite3()
   registry.conn = registry.env:connect(db_arg)
   registry.logger = io.open(log_arg, 'a')
   registry.time = datetime.format_timestamp(os.time(), 0)
   registry.cache = {}
   registry.json_out = {}
   timestamp()
end


hostaction = function (host)
   if registry.json_out[host.ip] == nil then
      registry.json_out[host.ip] = {
         ['timestamp'] = registry.time,
         ['ports'] = {}
      }
   end
end


portaction = function (host, port)
   local matches = {['data'] = {['nmap'] = {}, ['http'] = {}}, ['size'] = 0}
   if registry.json_out[host.ip] == nil then
      registry.json_out[host.ip] = {
         ['timestamp'] = registry.time,
         ['ports'] = {}
      }
   end
   if (port.version ~= nil
       and port.version.cpe[1] ~= nil
       and port.version.version ~= nil) then
      add_cpe_version(port.version.cpe[1], port.version.version, matches, 'nmap')
      add_cpe_aliases(port.version.cpe[1], port.version.version, matches, 'nmap')
   end
   if http_arg == '1'
      and (shortport.http(host, port)
           or shortport.ssl(host, port)
           or port.service == 'upnp') then
      http_match(host, port, matches)
   end
   local vulns
   if matches['size'] ~= 0 then
      vulns = analysis(host, port, matches)
   end
   return vulns
end


postaction = function ()
   registry.conn:close()
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
action = function (...) return ActionsTable[SCRIPT_TYPE](...) end
