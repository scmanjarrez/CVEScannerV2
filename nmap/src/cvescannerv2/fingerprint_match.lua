-- SPDX-License-Identifier: GPL-3.0-or-later
-- Fingerprint matching against catalogue rules and response text.  (Layer L3)
--
-- Pure text matching over HTTP response subjects, banners and probe
-- extractors: no network, file or database I/O. Reads the catalogue
-- (fingerprints, probes) from state; detected versions are recorded
-- through the matches module.

local state = require 'cvescannerv2.state'
local match_table = require 'cvescannerv2.match_table'

local M = {}

local add_cpe_version = match_table.add_cpe_version

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

--- Return the value of an HTML attribute in a tag, or nil.
local function html_attribute(tag, name)
  local pattern = case_insensitive_pattern(name)
  local value = tag:match(pattern .. '%s*=%s*"([^"]*)"')
  if value then return value end
  value = tag:match(pattern .. "%s*=%s*'([^']*)'")
  if value then return value end
  return tag:match(pattern .. '%s*=%s*([^%s>]+)')
end

--- Return the response text grouped by subject channel.
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

--- Return a trimmed version string, or nil when unsafe.
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

--- Return the version captured near an anchor, or nil.
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

--- Record rule matches and triggered probes for subjects.
local function match_subjects(subjects, matches, location, triggered,
    only_403)
  if not state.catalog_loaded then return end
  for channel, values in pairs(subjects) do
    local rules = state.catalog.fingerprints[channel] or {}
    for _, subject in ipairs(values) do
      for _, rule in ipairs(rules) do
        if not only_403 or rule.accept_403 then
          match_fingerprint_rule(rule, subject, matches, location)
        end
      end
    end
  end
  -- 403 pages only feed the rules that opt in; no probes are triggered.
  if only_403 then return end
  for _, probe in ipairs(state.catalog.probes) do
    if not triggered[probe.alias] and probe_detects(probe, subjects) then
      triggered[probe.alias] = true
    end
  end
end

--- Match the Nmap service banner against catalogue rules.
local function match_banner(port, matches, triggered)
  if not state.catalog_loaded or not port.version then return end
  local banner = port.version.service_fp
  if type(banner) ~= 'string' or banner == '' then return end
  local subjects = { banner = {} }
  for line in banner:gmatch('[^\r\n]+') do
    table.insert(subjects.banner, line)
  end
  match_subjects(subjects, matches, 'nmap', triggered)
end

--- Return the version extracted by a probe from body, or nil.
local function extract_probe_version(probe, body)
  for _, extractor in ipairs(probe.extract) do
    if anchor_matches(extractor.anchor, body) then
      local version = anchored_capture(extractor.regex,
        extractor.anchor, body)
      if version then return version end
    end
  end
  return nil
end

M.html_attribute = html_attribute
M.response_subjects = response_subjects
M.safe_version = safe_version
M.anchored_capture = anchored_capture
M.match_subjects = match_subjects
M.match_banner = match_banner
M.extract_probe_version = extract_probe_version

return M
