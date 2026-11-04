-- SPDX-License-Identifier: GPL-3.0-or-later
-- Pure validation of the vulners catalogue JSON files.

-- Checks the decoded fingerprints, paths and probes tables and builds the
-- in-memory catalogue. Performs no network or file I/O.

local M = {}

local CATALOG_SCHEMA = 1
local MAX_CATALOG_BYTES = 8 * 1024 * 1024
local MAX_CATALOG_RULES = 20000
local MAX_CATALOG_PATHS = 2000
local MAX_CATALOG_PROBES = 500
local MAX_CATALOG_STRING = 2048


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
            or #rule.anchor > MAX_CATALOG_STRING))
        or (rule.accept_403 ~= nil
          and type(rule.accept_403) ~= 'boolean') then
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
      accept_403 = rule.accept_403 == true,
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

M.MAX_CATALOG_BYTES = MAX_CATALOG_BYTES
M.class_end = class_end
M.capture_count = capture_count
M.valid_pattern = valid_pattern
M.valid_alias = valid_alias
M.valid_channel = valid_channel
M.valid_path = valid_path
M.validate_fingerprints = validate_fingerprints
M.validate_paths = validate_paths
M.validate_probes = validate_probes
M.build_catalog = build_catalog

return M
