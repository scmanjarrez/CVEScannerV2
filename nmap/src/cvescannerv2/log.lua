-- SPDX-License-Identifier: GPL-3.0-or-later
-- Log file I/O for the cvescannerv2 NSE script.  (Layer L2)
--
-- Appends to the log file opened in state.log_file (io.open, append mode)
-- and prints run details through stdnse. The lines are built by
-- text_output; this module only writes them. Does no network I/O and does
-- not read config.

local M = {}


local stdnse = require 'stdnse'

local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local fmt = util.fmt


--- Open the log file in append mode and keep it in the shared state.
local function open(path)
  state.log_file = io.open(path, 'a')
end
M.open = open


--- Write a final newline and close the log file kept in the shared state.
local function close()
  state.log_file:write("\n")
  state.log_file:close()
end
M.close = close


--- Print the run details through stdnse.
local function log_run_header(script_version)
  stdnse.verbose(1, fmt("Timestamp: %s", state.run_timestamp))
  stdnse.verbose(1, fmt("CVE data source: %s", "nvd.nist.gov"))
  stdnse.verbose(1, fmt("Script version: %s", script_version))
end
M.log_run_header = log_run_header


--- Write a formatted line to the log file.
local function write(msg, ...)
  state.log_file:write(fmt(msg .. "\n", ...))
end
M.write = write


--- Write each line of a list to the log file, one per row.
local function write_lines(lines)
  for _, line in ipairs(lines) do
    state.log_file:write(line .. "\n")
  end
end
M.write_lines = write_lines


return M
