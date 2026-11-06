-- SPDX-License-Identifier: GPL-3.0-or-later
-- Static checks of the NSE module tree under nmap/src/cvescannerv2/:
-- layering, cycles, ownership of Nmap and I/O APIs and implicit globals.
-- Nmap is not needed. Comments are ignored by stripping from each '--'.

local t = require 'harness'

local SRC = 'nmap/src/cvescannerv2'

-- Layer of every module. A module may only require modules whose layer is
-- strictly lower than its own.
local LAYER = {
  util = 0, state = 0, config = 0, cpe = 0,
  version = 1,
  match_table = 2, ['catalog.validate'] = 2, reference_files = 2,
  db = 2, log = 2, json_report = 2,
  ['catalog.tiers'] = 2,
  ['catalog.store'] = 3,
  fingerprint_match = 3, os_context = 3, sweep_evidence = 3,
  ['probes.smb'] = 3, ['probes.irc'] = 3, ['probes.ntp'] = 3,
  ['probes.upnp'] = 3,
  http_fingerprint = 4, ['probes.cups'] = 4,
  ['probes.init'] = 5, version_scope = 5, platform_match = 5,
  confidence = 5,
  port_matches = 6, text_output = 6,
  service_cves = 7,
  port_analysis = 8,
  lifecycle = 9,
}

-- Matches 'require "cvescannerv2.X"' with optional parentheses.
local REQUIRE = [=[require%s*%(?%s*['"]cvescannerv2%.([%w%._]+)['"]]=]

-- Nmap and I/O APIs and the only modules allowed to use them.
local OWNERS = {
  { api = 'get_script_args', owners = { 'config' } },
  { api = 'nmap.registry', owners = {} },
  { api = 'SCRIPT_NAME', owners = {} },
  { api = 'SCRIPT_PATH', owners = {} },
  { api = 'SCRIPT_TYPE', owners = {} },
  { api = 'luasql', owners = { 'db' } },
  { api = 'io.open', owners = {
    'util', 'catalog.store', 'reference_files', 'log', 'json_report' } },
}

local function fail(fmt, ...)
  error(string.format(fmt, ...), 0)
end

local function read(path)
  local file = assert(io.open(path, 'r'))
  local body = file:read('*all')
  file:close()
  return body
end

-- Lines of a Lua file without the '--' comments.
local function code_lines(body)
  local lines = {}
  for line in (body .. '\n'):gmatch('(.-)\n') do
    local code = line:gsub('%-%-.*$', '')
    table.insert(lines, code)
  end
  return lines
end

-- Map of module name to { path, lines, code } for every .lua file found.
-- A name is the relative path without '.lua' and with '.' as separator.
local function load_modules()
  local modules = {}
  local handle = io.popen(
    "find nmap/src/cvescannerv2 -name '*.lua' 2>/dev/null | sort")
  assert(handle, 'cannot list nmap/src/cvescannerv2')
  for path in handle:lines() do
    local name = path:sub(#SRC + 2)
    name = name:gsub('%.lua$', '')
    name = name:gsub('/', '.')
    local lines = code_lines(read(path))
    modules[name] = {
      path = path,
      lines = lines,
      code = table.concat(lines, '\n'),
    }
  end
  handle:close()
  return modules
end

local MODULES = load_modules()

local NAMES = {}
for name in pairs(MODULES) do table.insert(NAMES, name) end
table.sort(NAMES)

-- Map of module name to the list of modules it requires.
local DEPS = {}
for _, name in ipairs(NAMES) do
  DEPS[name] = {}
  for dep in MODULES[name].code:gmatch(REQUIRE) do
    table.insert(DEPS[name], dep)
  end
end

-- Return the list of names forming a cycle in DEPS, or nil.
local function find_cycle()
  local state = {}
  local stack = {}

  local function visit(name)
    if state[name] == 'done' then return nil end
    if state[name] == 'active' then
      local start = 1
      for i, item in ipairs(stack) do
        if item == name then start = i end
      end
      local cycle = {}
      for i = start, #stack do table.insert(cycle, stack[i]) end
      table.insert(cycle, name)
      return cycle
    end
    state[name] = 'active'
    table.insert(stack, name)
    for _, dep in ipairs(DEPS[name] or {}) do
      local cycle = visit(dep)
      if cycle then return cycle end
    end
    stack[#stack] = nil
    state[name] = 'done'
    return nil
  end

  for _, name in ipairs(NAMES) do
    local cycle = visit(name)
    if cycle then return cycle end
  end
  return nil
end

local function allows(owners, name)
  for _, owner in ipairs(owners) do
    if owner == name then return true end
  end
  return false
end

t.suite('architecture')

t.case('every module is listed in the layer table', function()
  for _, name in ipairs(NAMES) do
    if LAYER[name] == nil then
      fail('module %s (%s) is not in the layer table: add it to LAYER '
        .. 'in nmap/tests/lua/test_architecture.lua',
        name, MODULES[name].path)
    end
  end
end)

t.case('requires point to a strictly lower layer', function()
  for _, name in ipairs(NAMES) do
    local layer = LAYER[name]
    for _, dep in ipairs(DEPS[name]) do
      local dep_layer = LAYER[dep]
      if dep_layer == nil then
        fail('module %s requires %s, which is not in the layer table',
          name, dep)
      end
      if layer ~= nil and dep_layer >= layer then
        fail('module %s (layer %d) requires %s (layer %d): '
          .. 'a module may only require a lower layer',
          name, layer, dep, dep_layer)
      end
    end
  end
end)

t.case('require graph has no cycles', function()
  local cycle = find_cycle()
  if cycle then
    fail('require cycle: %s', table.concat(cycle, ' -> '))
  end
end)

t.case('Nmap and I/O APIs are used only by their owner modules', function()
  for _, rule in ipairs(OWNERS) do
    for _, name in ipairs(NAMES) do
      if not allows(rule.owners, name)
          and MODULES[name].code:find(rule.api, 1, true) then
        local owners = #rule.owners == 0 and 'no module'
          or table.concat(rule.owners, ', ')
        fail('module %s uses %s; allowed only in: %s',
          name, rule.api, owners)
      end
    end
  end
end)

t.case('modules declare no implicit globals', function()
  for _, name in ipairs(NAMES) do
    for number, line in ipairs(MODULES[name].lines) do
      local global = line:match('^([%a_][%w_]*)%s*=')
        or line:match('^function%s+([%a_][%w_]*)%s*%(')
      if global then
        fail('module %s line %d: global definition of %s '
          .. '(declare it with local or use the module table)',
          name, number, global)
      end
    end
  end
end)
