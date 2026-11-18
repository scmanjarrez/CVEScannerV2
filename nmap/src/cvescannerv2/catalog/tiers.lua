-- SPDX-License-Identifier: GPL-3.0-or-later
-- Classify catalogue paths into sweep tiers and group them.  (Layer L2)
--
-- Pure helpers: no network or file I/O, no Nmap calls and no dependency on
-- other scanner modules.

local M = {}

--- Core paths requested on every HTTP port, in request order.
M.CORE = {
  '/robots.txt',
  '/login',
  '/admin',
  '/admin/',
  '/api',
  '/api/',
  '/version',
  '/api/v1/version',
  '/manifest.json',
  '/healthz',
  '/metrics',
  '/index.html',
  '/health',
  '/info',
  '/console',
  '/readme.txt',
}

local CORE_SET = {}
for _, path in ipairs(M.CORE) do
  CORE_SET[path] = true
end

local function set_of(values)
  local result = {}
  for _, value in ipairs(values) do
    result[value] = true
  end
  return result
end

-- Checked in this order; the first family whose rule matches wins.
local FAMILIES = {
  {
    name = 'wordpress',
    prefixes = { '/wp-' },
    fragments = { '/wp-content/', '/wp-includes/', '/wp-admin/' },
    exts = {},
  },
  {
    name = 'domino',
    prefixes = { '/inotes/' },
    fragments = {},
    exts = set_of({ 'nsf' }),
  },
  {
    name = 'coldfusion',
    prefixes = {},
    fragments = {},
    exts = set_of({ 'cfm' }),
  },
  {
    name = 'aspnet',
    prefixes = {},
    fragments = {},
    exts = set_of({ 'asp', 'aspx', 'axd', 'asmx', 'ashx' }),
  },
  {
    name = 'java',
    prefixes = {},
    fragments = {},
    exts = set_of({ 'jsp', 'jhtml', 'jsa', 'do', 'action' }),
  },
  {
    name = 'cgi',
    prefixes = { '/cgi-bin/' },
    fragments = {},
    exts = set_of({ 'cgi', 'pl', 'shtml' }),
  },
  {
    name = 'php',
    prefixes = {},
    fragments = {},
    exts = set_of({ 'php' }),
  },
}

--- Return the path without its query string or fragment.
--
-- Args:
--   path: Request path, possibly with '?query' or '#fragment'.
--
-- Returns:
--   The path up to the first '?' or '#'.
local function strip_query(path)
  return path:match('^[^?#]*')
end

--- Return the lowercase extension of the last path segment, or nil.
--
-- Args:
--   lower_path: Lowercase path without query string.
--
-- Returns:
--   The extension without the dot, or nil when there is none.
local function extension(lower_path)
  return lower_path:match('%.([^./]*)$')
end

--- Return the family name that owns a lowercase path, or nil.
--
-- Args:
--   lower_path: Lowercase path without query string.
--
-- Returns:
--   The first matching family name, or nil.
local function family_of(lower_path)
  local ext = extension(lower_path)
  for _, family in ipairs(FAMILIES) do
    for _, prefix in ipairs(family.prefixes) do
      if lower_path:sub(1, #prefix) == prefix then
        return family.name
      end
    end
    for _, fragment in ipairs(family.fragments) do
      if lower_path:find(fragment, 1, true) then
        return family.name
      end
    end
    if ext ~= nil and family.exts[ext] then
      return family.name
    end
  end
  return nil
end

--- Classify a request path into a sweep tier.
--
-- The query string and fragment are ignored. Core paths are matched
-- exactly, then families by prefix, fragment or extension, and anything
-- else is 'tail'. The root path '/' is classified as 'tail'.
--
-- Args:
--   path: Request path to classify.
--
-- Returns:
--   'core', 'family:<name>' or 'tail'.
function M.classify(path)
  local clean = strip_query(path)
  if CORE_SET[clean] then
    return 'core'
  end
  local family = family_of(clean:lower())
  if family ~= nil then
    return 'family:' .. family
  end
  return 'tail'
end

--- Group paths into core, family and tail lists.
--
-- Walks paths in their original order and skips exact duplicates. The core
-- list holds the raw path strings whose canonical form (query and fragment
-- stripped) is a CORE entry, grouped by CORE order and keeping each group's
-- original order, so queries such as '/x?a=1' are emitted intact. Family and
-- tail lists keep the original order and raw path strings. Only families with
-- at least one path appear in the families table.
--
-- Args:
--   paths: List of request paths.
--
-- Returns:
--   A table with fields core (list), families (name to list) and tail
--   (list).
function M.build(paths)
  local result = { core = {}, families = {}, tail = {} }
  local seen = {}
  local core_groups = {}
  for _, path in ipairs(paths) do
    if not seen[path] then
      seen[path] = true
      local tier = M.classify(path)
      if tier == 'core' then
        local canon = strip_query(path)
        core_groups[canon] = core_groups[canon] or {}
        table.insert(core_groups[canon], path)
      elseif tier == 'tail' then
        table.insert(result.tail, path)
      else
        local name = tier:match('^family:(.+)$')
        result.families[name] = result.families[name] or {}
        table.insert(result.families[name], path)
      end
    end
  end
  for _, canon in ipairs(M.CORE) do
    for _, path in ipairs(core_groups[canon] or {}) do
      table.insert(result.core, path)
    end
  end
  return result
end

return M
