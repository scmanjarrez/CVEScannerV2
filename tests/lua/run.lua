-- SPDX-License-Identifier: GPL-3.0-or-later
-- Run the Lua unit and integration suites from the repository root:
--   lua5.4 tests/lua/run.lua
-- Environment:
--   CVESCANNER_STRICT=1   fail when known bugs are still present (or fixed)
--   CVESCANNER_FILTER=txt run only tests whose "suite :: name" contains txt
--   CVESCANNER_NSE=path   scanner script to test (default cvescannerv2.nse)

package.path = 'tests/lua/?.lua;' .. package.path

local t = require 'harness'

local SUITES = {
  'tests/lua/test_versions.lua',
  'tests/lua/test_scoping.lua',
  'tests/lua/test_catalog.lua',
  'tests/lua/test_database.lua',
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
