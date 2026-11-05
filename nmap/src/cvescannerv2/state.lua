-- SPDX-License-Identifier: GPL-3.0-or-later
-- Shared state for the cvescannerv2 NSE script.  (Layer L0)
--
-- This module is the only place where data is shared between script threads.
-- It replaces nmap.registry[SCRIPT_NAME]. The module table is the state.
-- No I/O and no config reads. Other modules read and write its fields.

local M = {}

-- Return fresh initial values. Tables are new on every call.
local function defaults()
  return {
    product_aliases = {},
    vendor_aliases = {},
    product_cpe = {},
    platform_families = {},
    host_os_family = {},
    smb_info = {},
    ntp_info = {},
    host_os_probe_result = {},
    catalog = { fingerprints = {}, paths = {}, probes = {} },
    catalog_loaded = false,
    probe_cache = {},
    enabled = true,
  }
end

--- Reset the state to its initial values. Functions are kept.
function M.reset()
  for key, value in pairs(M) do
    if type(value) ~= 'function' then M[key] = nil end
  end
  for key, value in pairs(defaults()) do M[key] = value end
end

M.reset()

return M
