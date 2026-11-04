-- SPDX-License-Identifier: GPL-3.0-or-later
-- Pure string and file helpers shared by the cvescannerv2 NSE script.

local M = {}


local function empty(str)
  return str == nil or str == ''
end
M.empty = empty


local function exists(file)
  local f = io.open(file, 'r')
  return f ~= nil and f:close()
end
M.exists = exists


local function fmt(msg, ...)
  return msg:format(...)
end
M.fmt = fmt

local function sql_escape(value)
  return (tostring(value):gsub("'", "''"))
end
M.sql_escape = sql_escape

-- Implementation of named parameters from RiciLake@lua-users. A table value
-- becomes a comma-separated list of quoted literals, e.g. 'a', 'b'.
local function fmtn(msg, tab)
  return (msg:gsub(
    '($%b{})',
    function(nparam)
      -- nparam -> ${var} => nparam:sub(3, -2) -> var
      local value = tab[nparam:sub(3, -2)]
      if value == nil then return "nil" end
      if type(value) == 'table' then
        local literals = {}
        for i, item in ipairs(value) do
          literals[i] = "'" .. sql_escape(item) .. "'"
        end
        return table.concat(literals, ', ')
      end
      return sql_escape(value)
    end
  ))
end
M.fmtn = fmtn


return M
