-- IRC version probe for UnrealIRCd services.
--
-- Registers on the IRC port and reads the 351 (VERSION) reply to get
-- the exact UnrealIRCd version.

local nmap = require 'nmap'
local stdnse = require 'stdnse'

local M = {}

local IRC_SERVICES = { irc = true, ircs = true }
local IRC_REGISTER = 'NICK cvescan\r\nUSER cvescan 0 * :cvescan\r\n'
  .. 'VERSION\r\n'
local IRC_MAX_READS = 10
local IRC_RETRY_DELAY = 20

--- Return the UnrealIRCd version from a 351 (VERSION) reply line.
-- Return nil when the server name is not an Unreal version string.
local function irc_unreal_version(line)
  local token = line:match('^:%S+ 351 %S+ (%S+)')
  local version = token and token:match('^Unreal(%d[%w%.]*)')
  if version == nil then return nil end
  return (version:gsub('%.$', ''))
end

--- Return whether an IRC line is the server's throttling error.
-- UnrealIRCd answers 'ERROR :Closing Link: ... (Throttled ...)'.
local function irc_is_throttled(line)
  return line:match('^ERROR') ~= nil and line:find('Throttled', 1, true) ~= nil
end

--- Read IRC lines until the 351 reply, answering PING with PONG.
-- Return the UnrealIRCd version, or nil on timeout or error. The second
-- value is true when the server closed the link as throttled.
local function irc_read_version(sock)
  for _ = 1, IRC_MAX_READS do
    local ok, data = sock:receive_lines(1)
    if not ok or type(data) ~= 'string' then return nil, false end
    for line in data:gmatch('[^\r\n]+') do
      local ping = line:match('^PING :(.*)$')
      if ping then
        sock:send('PONG ' .. ping .. '\r\n')
      elseif irc_is_throttled(line) then
        return nil, true
      elseif line:match('^:%S+ 351 ') then
        return irc_unreal_version(line), false
      end
    end
  end
  return nil, false
end

--- Send the registration and VERSION requests on an open socket.
-- Return the UnrealIRCd version (or nil) and the throttled flag.
local function irc_exchange(sock, host, port)
  if not sock:connect(host, port) then return nil, false end
  sock:send(IRC_REGISTER)
  return irc_read_version(sock)
end

--- Run one IRC exchange on a new socket that is always closed.
-- Return the UnrealIRCd version (or nil) and the throttled flag. Errors
-- raised by the socket count as a plain failure.
local function irc_attempt(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok, version, throttled = pcall(irc_exchange, sock, host, port)
  sock:close()
  if not ok then return nil, false end
  return version, throttled
end

--- Return the UnrealIRCd CPE and exact version from its VERSION reply.
-- A throttled server is retried once on a new socket after 20 seconds.
-- Return nil when the service does not answer with a 351 reply.
local function irc_probe(host, port)
  local version, throttled = irc_attempt(host, port)
  if throttled then
    stdnse.verbose(2, 'irc throttled on %s:%d, retrying', host.ip, port.number)
    stdnse.sleep(IRC_RETRY_DELAY)
    version = irc_attempt(host, port)
  end
  if version == nil then return nil end
  return { cpe = 'cpe:/a:unrealircd:unrealircd', version = version }
end

local IRC_PROBE = {
  name = 'irc',
  kind = 'version',
  products = { unrealircd = true },
  services = IRC_SERVICES,
  run = irc_probe,
}

M.IRC_SERVICES = IRC_SERVICES
M.IRC_REGISTER = IRC_REGISTER
M.IRC_MAX_READS = IRC_MAX_READS
M.IRC_RETRY_DELAY = IRC_RETRY_DELAY
M.irc_unreal_version = irc_unreal_version
M.irc_is_throttled = irc_is_throttled
M.irc_read_version = irc_read_version
M.irc_exchange = irc_exchange
M.irc_attempt = irc_attempt
M.irc_probe = irc_probe
M.IRC_PROBE = IRC_PROBE

return M
