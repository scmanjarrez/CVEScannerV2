-- SPDX-License-Identifier: GPL-3.0-or-later
-- Run the Lua unit and integration suites from the repository root:
--   lua5.4 nmap/tests/lua/run.lua
-- Environment:
--   CVESCANNER_STRICT=1   fail when known bugs are still present (or fixed)
--   CVESCANNER_FILTER=txt run only tests whose "suite :: name" contains txt
--   CVESCANNER_NSE=path   scanner script to test (default nmap/src/cvescannerv2.nse)

package.path = 'nmap/tests/lua/?.lua;' .. package.path

local t = require 'harness'

local SUITES = {
  'nmap/tests/lua/test_versions.lua',
  'nmap/tests/lua/test_scoping.lua',
  'nmap/tests/lua/test_output.lua',
  'nmap/tests/lua/test_catalog.lua',
  'nmap/tests/lua/test_database.lua',
  'nmap/tests/lua/test_docker.lua',
  'nmap/tests/lua/test_tiers.lua',
  'nmap/tests/lua/test_sweep_evidence.lua',
  'nmap/tests/lua/test_architecture.lua',
}

for _, suite in ipairs(SUITES) do
  local ok, err = pcall(dofile, suite)
  if not ok then
    t.results.failed = t.results.failed + 1
    table.insert(t.results.failures, suite .. ' aborted: ' .. tostring(err))
    print('  ABORT ' .. suite .. '\n      ' .. tostring(err))
  end
end

os.exit(t.summary() and 0 or 1)
