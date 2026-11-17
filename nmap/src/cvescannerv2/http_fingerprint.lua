-- SPDX-License-Identifier: GPL-3.0-or-later
-- HTTP fingerprint engine for the cvescannerv2 NSE script.  (Layer L4)
--
-- Reads HTTP responses from a port (network I/O through the Nmap http
-- library, paced by nmap.timing_level) and feeds them to the fingerprint
-- and version matchers: targeted probes and the optional catalogue sweep.
-- Reads state.catalog and config (sweep_level, sweep_budget, maxredirect,
-- options_for_target).

local http = require 'http'
local nmap = require 'nmap'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local config = require 'cvescannerv2.config'
local fingerprint = require 'cvescannerv2.fingerprint_match'
local match_table = require 'cvescannerv2.match_table'
local state = require 'cvescannerv2.state'
local sweep_evidence = require 'cvescannerv2.sweep_evidence'
local tiers = require 'cvescannerv2.catalog.tiers'
local util = require 'cvescannerv2.util'
local version = require 'cvescannerv2.version'

local M = {}

local fmt = util.fmt
local add_cpe_version = match_table.add_cpe_version
local cpe_has_precise_version = match_table.cpe_has_precise_version
local prune_series_versions = match_table.prune_series_versions
local is_precise_version = version.is_precise_version
local match_subjects = fingerprint.match_subjects
local extract_probe_version = fingerprint.extract_probe_version
local response_subjects = fingerprint.response_subjects


--- Return true when the response status is 2xx or 3xx.
local function response_is_usable(response)
  local status = tonumber(response.status)
  return status ~= nil and status >= 200 and status < 400
end


--- Fetch the paths of triggered probes and record their versions.
local function run_targeted_probes(host, port, matches, triggered)
  local probes_used = 0
  for _, probe in ipairs(state.catalog.probes) do
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
        local response = http.get(host, port, path,
          config.options_for_target())
        if type(response) == 'table' and response_is_usable(response) then
          local body = response.body
          if type(body) == 'string' then
            local ver = extract_probe_version(probe, body)
            if ver then
              add_cpe_version(probe.alias, ver, matches, 'http')
              if is_precise_version(ver) then
                prune_series_versions(matches, probe.alias, ver)
              end
            end
          end
        end
      end
    end
  end
end

--- Return the subjects without the page-specific channels.
--
-- Catch-all pages answer every path with the same content, so their body,
-- title, script and meta channels say nothing about the application.
--
-- Args:
--   subjects: Subjects table keyed by channel.
--
-- Returns:
--   A new subjects table without body, title, script and meta channels.
local function without_page_channels(subjects)
  local kept = {}
  for channel, values in pairs(subjects) do
    if channel ~= 'body' and channel ~= 'title' and channel ~= 'script'
        and channel:sub(1, 5) ~= 'meta:' then
      kept[channel] = values
    end
  end
  return kept
end

--- Return the sweep families with evidence, Nmap families first.
--
-- Args:
--   plan: Tier plan with a families table keyed by family name.
--   evidence: Set of families with evidence so far.
--   nmap_families: Set of families seen in the Nmap port version.
--
-- Returns:
--   Sorted list of family names with evidence and planned paths.
local function active_families(plan, evidence, nmap_families)
  local names = {}
  for family in pairs(plan.families) do
    if evidence[family] then
      table.insert(names, family)
    end
  end
  table.sort(names, function(a, b)
    local a_nmap = nmap_families[a] == true
    local b_nmap = nmap_families[b] == true
    if a_nmap ~= b_nmap then
      return a_nmap
    end
    return a < b
  end)
  return names
end

--- Request paths in paced batches and hand each reply to handle.
--
-- Paths already visited are skipped and the budget caps the requests.
-- Redirects are reissued through get() without counting as requests.
--
-- Args:
--   host: Target host table.
--   port: Target port table.
--   paths: Request paths in order.
--   ctx: Sweep context with visited (set), used (count) and budget.
--   handle: Function called as handle(path, response) for each reply.
--
-- Returns:
--   False when a batch got no answer at all, true otherwise.
local function request_batch(host, port, paths, ctx, handle)
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
  local todo = {}
  for _, path in ipairs(paths) do
    if not ctx.visited[path] and ctx.used < ctx.budget then
      ctx.visited[path] = true
      ctx.used = ctx.used + 1
      table.insert(todo, path)
    end
  end
  local start = 1
  while start <= #todo do
    local requests = nil
    local finish = math.min(start + batch_size - 1, #todo)
    for idx = start, finish do
      requests = http.pipeline_add(todo[idx],
        config.options_for_target(), requests)
    end
    local responses = http.pipeline_go(host, port, requests)
    local answered = false
    if type(responses) == 'table' then
      for idx, response in ipairs(responses) do
        local path = todo[start + idx - 1]
        if type(response) == 'table' and response.status ~= nil then
          answered = true
        end
        if type(response) == 'table' and config.maxredirect > 0 then
          local status = tonumber(response.status)
          if status == 301 or status == 302 or status == 303
              or status == 307 or status == 308 then
            -- Pipelines do not follow redirects. Reissue this path through
            -- get() to apply Nmap's redirect checks and maxredirect limit.
            response = http.get(host, port, path,
              config.options_for_target())
          end
        end
        if type(response) == 'table' then
          handle(path, response)
        end
      end
    end
    if not answered then
      return false
    end
    start = finish + 1
    if delay > 0 and start <= #todo then stdnse.sleep(delay) end
  end
  return true
end

--- Run the tiered catalogue sweep for one HTTP port.
--
-- Tier T0 requests '/' and a random missing path that reveals soft 404
-- pages. Tier T1 requests the core paths. Tier T2 requests the families
-- with evidence and the tail paths linked from received pages. Tier T3,
-- only with sweep_level 2, requests every remaining catalogue path. Each
-- request counts against the per-port budget.
--
-- Args:
--   host: Target host table.
--   port: Target port table.
--   matches: Match table that receives rule matches.
--   triggered: Set of probe aliases triggered by the replies.
local function sweep_catalog(host, port, matches, triggered)
  local plan = state.catalog.sweep or tiers.build(state.catalog.paths)
  local budget = config.sweep_budget
  if config.sweep_level == 2 and not config.sweep_budget_set then
    budget = math.huge
  end
  local ctx = { visited = {}, used = 0, budget = budget }
  local evidence = sweep_evidence.families({}, port.version)
  local nmap_families = {}
  for family in pairs(evidence) do
    nmap_families[family] = true
  end
  local linked = {}
  local soft_body = nil
  local soft_body_known = false
  local root_response = nil
  local useful = 0
  local random_path = '/' .. string.format('%08x%08x',
    math.random(0, 0xffffffff), math.random(0, 0xffffffff))

  local function handle(path, response)
    local status = tonumber(response.status)
    if path == random_path then
      if status ~= nil and status >= 200 and status < 300
          and type(response.body) == 'string' then
        soft_body = response.body
      end
      return
    end
    if path == '/' and not soft_body_known then
      root_response = response
      return
    end
    if response_is_usable(response) then
      local subjects = response_subjects(response)
      local catch_all = soft_body ~= nil and response.body == soft_body
      if catch_all and path ~= '/' then
        return
      end
      match_subjects(subjects, matches, 'http', triggered)
      if catch_all then
        subjects = without_page_channels(subjects)
      end
      useful = useful + 1
      for family in pairs(sweep_evidence.families(subjects, port.version)) do
        evidence[family] = true
      end
      for prefix in pairs(sweep_evidence.linked_prefixes(subjects)) do
        linked[prefix] = true
      end
    elseif status == 403 then
      match_subjects(response_subjects(response), matches, 'http',
        triggered, true)
    end
  end

  local function run_tier(tier, paths)
    if ctx.used >= ctx.budget then
      return true
    end
    local base = ctx.used
    useful = 0
    local answered = request_batch(host, port, paths, ctx, handle)
    local active = active_families(plan, evidence, nmap_families)
    stdnse.verbose(2, fmt(
      "sweep %s:%s tier=%s requested=%d useful=%d families=%s",
      host.ip, port.number, tier, ctx.used - base, useful,
      table.concat(active, ',')))
    if not answered then
      stdnse.verbose(2, fmt("No http answers on %s:%s; stopping sweep",
        host.ip, port.number))
    end
    return answered
  end

  local answered = run_tier('T0', { '/', random_path })
  soft_body_known = true
  if root_response ~= nil then
    handle('/', root_response)
  end
  if not answered then
    return
  end
  if not run_tier('T1', plan.core) then
    return
  end
  local family_paths = {}
  for _, family in ipairs(active_families(plan, evidence, nmap_families)) do
    for _, path in ipairs(plan.families[family]) do
      table.insert(family_paths, path)
    end
  end
  for _, path in ipairs(plan.tail) do
    if sweep_evidence.path_linked(path, linked) then
      table.insert(family_paths, path)
    end
  end
  if not run_tier('T2', family_paths) then
    return
  end
  if config.sweep_level == 2 then
    run_tier('T3', state.catalog.paths)
  end
end

--- Run the catalogue sweep and targeted probes when catalogue is loaded.
local function match_http_fingerprints(host, port, matches, triggered)
  if state.catalog_loaded then
    -- The tiered sweep runs from sweep_level 1; level 2 adds the tail.
    if config.sweep_level >= 1 then
      sweep_catalog(host, port, matches, triggered)
    end
    run_targeted_probes(host, port, matches, triggered)
  end
end


-- Services that Nmap identifies but that do not speak HTTP, even when
-- wrapped in TLS. The http engine must skip them.
local NON_HTTP_SERVICES = {
  ['ms-wbt-server'] = true,
  ['ms-sql-s'] = true,
  ['mysql'] = true,
  ['postgresql'] = true,
  ['ssh'] = true,
  ['ftp'] = true,
  ['ftps'] = true,
  ['smtp'] = true,
  ['smtps'] = true,
  ['imap'] = true,
  ['imaps'] = true,
  ['pop3'] = true,
  ['pop3s'] = true,
  ['ldap'] = true,
  ['ldapssl'] = true,
  ['ldaps'] = true,
  ['vnc'] = true,
  ['microsoft-ds'] = true,
  ['netbios-ssn'] = true,
  ['msrpc'] = true,
  ['telnet'] = true,
  ['domain'] = true,
  ['ntp'] = true,
  ['snmp'] = true,
}

--- Return true when the http fingerprint engine applies to a port.
-- Plain HTTP and upnp always qualify. TLS ports qualify unless the
-- service is known to speak a non-HTTP protocol.
local function use_http_engine(host, port)
  if shortport.http(host, port) or port.service == 'upnp' then
    return true
  end
  return shortport.ssl(host, port) and not NON_HTTP_SERVICES[port.service]
end


M.response_is_usable = response_is_usable
M.run_targeted_probes = run_targeted_probes
M.sweep_catalog = sweep_catalog
M.match_http_fingerprints = match_http_fingerprints
M.use_http_engine = use_http_engine

return M
