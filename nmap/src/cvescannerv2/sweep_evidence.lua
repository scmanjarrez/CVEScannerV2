-- SPDX-License-Identifier: GPL-3.0-or-later
-- Technology families and linked path prefixes from HTTP evidence.  (Layer L3)
--
-- Pure text matching over HTTP response subjects and port version fields: no
-- network, file, database or Nmap access. The sweep uses the families to pick
-- candidate paths and the linked prefixes to recognise application roots.

local M = {}

local MAX_SEGMENT = 40

local JAVA_SERVERS = {
  'tomcat', 'coyote', 'jetty', 'weblogic', 'jboss', 'wildfly', 'glassfish',
}

local CGI_SERVERS = {
  'apache', 'lighttpd', 'boa', 'goahead', 'thttpd', 'mini_httpd',
}

local WORDPRESS_PATHS = { '/wp-content/', '/wp-includes/' }

local function values(subjects, channel)
  return subjects[channel] or {}
end

local function push(list, value)
  if type(value) == 'string' then table.insert(list, value) end
end

--- Return true when any value contains one of the lowercase literals.
local function mentions(list, literals)
  for _, value in ipairs(list) do
    local lower = value:lower()
    for _, literal in ipairs(literals) do
      if lower:find(literal, 1, true) then return true end
    end
  end
  return false
end

--- Return true when any value starts with one of the lowercase prefixes.
local function starts_with(list, prefixes)
  for _, value in ipairs(list) do
    local lower = value:lower()
    for _, prefix in ipairs(prefixes) do
      if lower:sub(1, #prefix) == prefix then return true end
    end
  end
  return false
end

--- Return the Server headers, product and extrainfo as one list.
local function server_values(subjects, port_version)
  local list = {}
  for _, value in ipairs(values(subjects, 'hdr:server')) do
    push(list, value)
  end
  push(list, port_version.product)
  push(list, port_version.extrainfo)
  return list
end

--- Return the CPE strings of a port version as a list.
local function cpe_values(port_version)
  local list = {}
  if type(port_version.cpe) == 'table' then
    for _, cpe in ipairs(port_version.cpe) do push(list, cpe) end
  end
  return list
end

--- Return the set of technology families seen in the evidence.
function M.families(subjects, port_version)
  local pv = port_version or {}
  local cookies = values(subjects, 'cookie')
  local powered = values(subjects, 'hdr:x-powered-by')
  local servers = server_values(subjects, pv)
  local cpes = cpe_values(pv)
  local product = {}
  push(product, pv.product)
  local checks = {
    wordpress = mentions(values(subjects, 'meta:generator'), { 'wordpress' })
      or mentions(values(subjects, 'script'), WORDPRESS_PATHS)
      or mentions(values(subjects, 'body'), WORDPRESS_PATHS)
      or starts_with(cookies, { 'wordpress_' }),
    php = mentions(powered, { 'php' })
      or starts_with(cookies, { 'phpsessid=' })
      or mentions(product, { 'php' }),
    aspnet = #values(subjects, 'hdr:x-aspnet-version') > 0
      or mentions(powered, { 'asp.net' })
      or starts_with(cookies, { 'asp.net_sessionid=' })
      or mentions(servers, { 'iis', 'microsoft-httpapi' }),
    java = starts_with(cookies, { 'jsessionid=' })
      or mentions(servers, JAVA_SERVERS)
      or mentions(cpes, { 'tomcat', 'jetty' }),
    cgi = mentions(servers, CGI_SERVERS),
    coldfusion = starts_with(cookies, { 'cfid=', 'cftoken=' })
      or mentions(servers, { 'coldfusion' }),
    domino = mentions(servers, { 'domino' }),
  }
  local found = {}
  for name, hit in pairs(checks) do
    if hit then found[name] = true end
  end
  return found
end

--- Return the first path segment of a relative or http(s) URL, or nil.
local function url_segment(url)
  local trimmed = url:match('^%s*(.-)%s*$')
  local path = trimmed:match('^[Hh][Tt][Tt][Pp][Ss]?://[^/?#]*(/.*)$')
  if not path then
    if trimmed:sub(1, 1) ~= '/' or trimmed:sub(2, 2) == '/' then
      return nil
    end
    path = trimmed
  end
  local name = path:match('^/([^/?#]*)')
  if not name or name == '' or #name > MAX_SEGMENT then return nil end
  return '/' .. name:lower()
end

--- Return the href, src and action values found in an HTML body.
local function markup_links(body)
  local links = {}
  for name, _, value in body:gmatch('[%s<](%a+)%s*=%s*(["\'])(.-)%2') do
    local attribute = name:lower()
    if attribute == 'href' or attribute == 'src'
        or attribute == 'action' then
      table.insert(links, value)
    end
  end
  return links
end

--- Return the lowercase first segments of links in body and script src.
function M.linked_prefixes(subjects)
  local urls = {}
  for _, body in ipairs(values(subjects, 'body')) do
    for _, link in ipairs(markup_links(body)) do
      table.insert(urls, link)
    end
  end
  for _, src in ipairs(values(subjects, 'script')) do
    table.insert(urls, src)
  end
  local prefixes = {}
  for _, url in ipairs(urls) do
    local segment = url_segment(url)
    if segment then prefixes[segment] = true end
  end
  return prefixes
end

--- Return true when the first segment of path is a linked prefix.
function M.path_linked(path, prefixes)
  if type(path) ~= 'string' then return false end
  local segment = url_segment(path:match('^([^?#]*)'))
  return segment ~= nil and prefixes[segment] == true
end

return M
