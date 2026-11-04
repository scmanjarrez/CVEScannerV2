-- SPDX-License-Identifier: GPL-3.0-or-later
-- Pure CPE 2.2 and 2.3 string parser used by the cvescannerv2 NSE script.

local M = {}


local function split_cpe(cpe)
  local parts = {}
  local field = {}
  local escaped = false
  for i = 1, #cpe do
    local char = cpe:sub(i, i)
    if char == ':' and not escaped then
      table.insert(parts, table.concat(field))
      field = {}
    else
      table.insert(field, char)
      if char == '\\' and not escaped then
        escaped = true
      else
        escaped = false
      end
    end
  end
  table.insert(parts, table.concat(field))

  local offset
  if parts[1] == 'cpe' and parts[2] == '2.3' then
    offset = 3
  elseif parts[1] == 'cpe' and parts[2] and parts[2]:sub(1, 1) == '/' then
    offset = 2
  else
    return nil
  end

  local function unescape(value)
    return (value or ''):gsub('\\(.)', '%1')
  end
  local cpe_type = unescape(parts[offset])
  if cpe_type:sub(1, 1) == '/' then
    cpe_type = cpe_type:sub(2)
  end
  return parts, offset, cpe_type,
      unescape(parts[offset + 1]),
      unescape(parts[offset + 2]),
      unescape(parts[offset + 3]),
      unescape(parts[offset + 4])
end
M.split_cpe = split_cpe


return M
