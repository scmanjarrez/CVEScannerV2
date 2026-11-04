-- SPDX-License-Identifier: GPL-3.0-or-later
-- Operating system context derived from Nmap and catalogue data.

-- Read-only with respect to probes: only a cached host_probe_os result is
-- used. State is read on every call from the shared state module.

local cpe_lib = require 'cvescannerv2.cpe'
local state = require 'cvescannerv2.state'

local split_cpe = cpe_lib.split_cpe

local M = {}


local OS_NAME_FAMILIES = {
  linux = 'linux',
  windows = 'windows',
  ['mac os x'] = 'macos',
  macos = 'macos',
  freebsd = 'bsd',
  openbsd = 'bsd',
  netbsd = 'bsd',
  solaris = 'solaris',
}

local DISTRO_NAMES = {
  { 'ubuntu', 'ubuntu' },
  { 'debian', 'debian' },
  { 'red hat', 'redhat' },
  { 'centos', 'centos' },
  { 'suse', 'suse' },
}

local BACKPORT_PATTERNS = {
  'ubuntu%d', 'debian', '%(ubuntu%)', '%(debian%)',
  '%f[%a]el%d', '%f[%a]deb%d', 'red hat',
}

local function version_text(port)
  local info = port.version or {}
  return string.lower(
    (info.version or '') .. ' ' .. (info.extrainfo or '')
  )
end

local function name_family(name)
  if type(name) ~= 'string' then return nil end
  return OS_NAME_FAMILIES[string.lower(name)]
end

local function vendor_family(vendor)
  if type(vendor) ~= 'string' then return nil end
  return state.platform_families[string.lower(vendor)]
end

local function family_from_cpe(cpe)
  local _, _, kind, vendor = split_cpe(cpe)
  if kind ~= 'o' then return nil end
  return vendor_family(vendor)
end

local function cpes_family(cpes)
  for _, cpe in ipairs(cpes or {}) do
    local family = family_from_cpe(cpe)
    if family then return family end
  end
  return nil
end

local function first_host_os_family(host)
  local matches = host.os
  if type(matches) ~= 'table' or type(matches[1]) ~= 'table' then
    return nil
  end
  local first = matches[1]
  local family = cpes_family(first.cpe)
  for _, class in ipairs(first.classes or first.osclass or {}) do
    family = family or cpes_family(class.cpe)
      or name_family(class.osfamily) or vendor_family(class.vendor)
  end
  return family
end

-- Cache the host.os family per IP; false marks a negative result.
local function host_os_family(host)
  if state.host_os[host.ip] == nil then
    local ok, family = pcall(first_host_os_family, host)
    state.host_os[host.ip] = ok and family or false
  end
  return state.host_os[host.ip] or nil
end

local function text_os(port)
  local text = version_text(port)
  for _, entry in ipairs(DISTRO_NAMES) do
    if text:find(entry[1], 1, true) then return 'linux', entry[2] end
  end
  if text:find('windows', 1, true) then return 'windows', nil end
  return nil, nil
end

-- Read-only: only a result cached by host_probe_os is used, never a probe.
local function os_context(host, port)
  local probed = state.host_os_probe[host.ip]
  if probed then
    return { family = probed.family, source = probed.source }
  end
  local info = port.version or {}
  local family, source = cpes_family(info.cpe), 'cpe'
  if family == nil then
    family, source = name_family(info.ostype), 'ostype'
  end
  if family == nil then
    family, source = host_os_family(host), 'host_os'
  end
  local text_family, distro = text_os(port)
  if family == nil then
    family, source = text_family, 'extrainfo'
  end
  if family == nil then return {} end
  return { family = family, distro = distro, source = source }
end

local function distro_backport(port)
  local text = version_text(port)
  for _, pattern in ipairs(BACKPORT_PATTERNS) do
    if text:find(pattern) then return true end
  end
  return false
end

M.OS_NAME_FAMILIES = OS_NAME_FAMILIES
M.DISTRO_NAMES = DISTRO_NAMES
M.BACKPORT_PATTERNS = BACKPORT_PATTERNS
M.version_text = version_text
M.name_family = name_family
M.vendor_family = vendor_family
M.family_from_cpe = family_from_cpe
M.cpes_family = cpes_family
M.first_host_os_family = first_host_os_family
M.host_os_family = host_os_family
M.text_os = text_os
M.os_context = os_context
M.distro_backport = distro_backport


return M
