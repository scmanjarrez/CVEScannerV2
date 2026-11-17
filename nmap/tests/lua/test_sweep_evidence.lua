-- SPDX-License-Identifier: GPL-3.0-or-later
-- Technology families, linked path prefixes and path linking for the sweep.

local t = require 'harness'
local evidence = require 'cvescannerv2.sweep_evidence'

local families = evidence.families
local linked = evidence.linked_prefixes
local path_linked = evidence.path_linked

t.suite('sweep evidence')

t.case('wordpress from generator meta', function()
  t.keys_eq(families({ ['meta:generator'] = { 'WordPress 6.4' } }, nil),
    { 'wordpress' })
end)

t.case('wordpress from wp-content script', function()
  t.keys_eq(families({ script = { '/wp-content/themes/x.js' } }, nil),
    { 'wordpress' })
end)

t.case('wordpress from wp-includes body', function()
  t.keys_eq(families({ body = { '<link href="/WP-INCLUDES/a.css">' } }, nil),
    { 'wordpress' })
end)

t.case('wordpress from cookie prefix', function()
  t.keys_eq(families({ cookie = { 'wordpress_logged_in=1' } }, nil),
    { 'wordpress' })
end)

t.case('php from x-powered-by', function()
  t.keys_eq(families({ ['hdr:x-powered-by'] = { 'PHP/8.1' } }, nil),
    { 'php' })
end)

t.case('php from phpsessid cookie', function()
  t.keys_eq(families({ cookie = { 'PHPSESSID=abc' } }, nil), { 'php' })
end)

t.case('php from port product', function()
  t.keys_eq(families({}, { product = 'PHP cli server' }), { 'php' })
end)

t.case('aspnet from x-aspnet-version header', function()
  t.keys_eq(families({ ['hdr:x-aspnet-version'] = { '4.0.30319' } }, nil),
    { 'aspnet' })
end)

t.case('aspnet from x-powered-by asp.net', function()
  t.keys_eq(families({ ['hdr:x-powered-by'] = { 'ASP.NET' } }, nil),
    { 'aspnet' })
end)

t.case('aspnet from asp.net_sessionid cookie', function()
  t.keys_eq(families({ cookie = { 'ASP.NET_SessionId=x' } }, nil),
    { 'aspnet' })
end)

t.case('aspnet from IIS server header', function()
  t.keys_eq(families({ ['hdr:server'] = { 'Microsoft-IIS/10.0' } }, nil),
    { 'aspnet' })
end)

t.case('aspnet from microsoft-httpapi product', function()
  t.keys_eq(families({}, { product = 'Microsoft-HTTPAPI' }), { 'aspnet' })
end)

t.case('java from jsessionid cookie', function()
  t.keys_eq(families({ cookie = { 'JSESSIONID=1A2B' } }, nil), { 'java' })
end)

t.case('java from tomcat server header', function()
  t.keys_eq(families({ ['hdr:server'] = { 'Apache-Coyote/1.1' } }, nil),
    { 'java', 'cgi' })
end)

t.case('java from jetty product', function()
  t.keys_eq(families({}, { product = 'Jetty' }), { 'java' })
end)

t.case('java from tomcat cpe', function()
  t.keys_eq(families({}, { cpe = { 'cpe:/a:apache:tomcat:9.0' } }),
    { 'java' })
end)

t.case('java from jetty cpe', function()
  t.keys_eq(families({}, { cpe = { 'cpe:/a:eclipse:jetty:9' } }), { 'java' })
end)

t.case('cgi from apache server header', function()
  t.keys_eq(families({ ['hdr:server'] = { 'Apache/2.4.41' } }, nil),
    { 'cgi' })
end)

t.case('cgi from lighttpd product', function()
  t.keys_eq(families({}, { product = 'lighttpd' }), { 'cgi' })
end)

t.case('coldfusion from cfid cookie', function()
  t.keys_eq(families({ cookie = { 'CFID=123' } }, nil), { 'coldfusion' })
end)

t.case('coldfusion from cftoken cookie', function()
  t.keys_eq(families({ cookie = { 'cftoken=9' } }, nil), { 'coldfusion' })
end)

t.case('coldfusion from server product', function()
  t.keys_eq(families({}, { product = 'Adobe ColdFusion' }), { 'coldfusion' })
end)

t.case('domino from server header', function()
  t.keys_eq(families({ ['hdr:server'] = { 'Lotus-Domino' } }, nil),
    { 'domino' })
end)

t.case('no families from empty headers', function()
  t.keys_eq(families({ ['hdr:server'] = { '' } }, {}), {})
end)

t.case('no families from nginx without markers', function()
  local subjects = {
    ['hdr:server'] = { 'nginx/1.18.0' },
    body = { '<html><body>Welcome</body></html>' },
  }
  t.keys_eq(families(subjects, { product = 'nginx' }), {})
end)

t.case('nil port version is accepted', function()
  t.keys_eq(families({ ['hdr:server'] = { 'Apache' } }, nil), { 'cgi' })
  t.keys_eq(families({}, nil), {})
end)

t.case('port version with nil fields is accepted', function()
  t.keys_eq(families({}, {}), {})
  t.keys_eq(families({}, { product = nil, cpe = nil }), {})
end)

t.case('family matching ignores case', function()
  t.keys_eq(families({ cookie = { 'jSessionId=Z' } }, nil), { 'java' })
  t.keys_eq(families({}, { product = 'DOMINO' }), { 'domino' })
end)

t.case('linked prefixes from relative href', function()
  local body = '<a href="/nacos/console/index">x</a>'
  t.keys_eq(linked({ body = { body } }), { '/nacos' })
end)

t.case('linked prefixes from absolute href drop the host', function()
  local body = '<a href="http://10.0.0.1:8080/Sonar/x">x</a>'
  t.keys_eq(linked({ body = { body } }), { '/sonar' })
end)

t.case('linked prefixes from https absolute src and action', function()
  local body = '<img src=\'https://ex.test/nifi-api/a.png\'>'
      .. '<form action="/app?x=1"></form>'
  t.keys_eq(linked({ body = { body } }), { '/nifi-api', '/app' })
end)

t.case('linked prefixes from script src', function()
  t.keys_eq(linked({ script = { '/static/app/main.js' } }), { '/static' })
end)

t.case('linked prefixes skip unsupported links', function()
  local body = '<a href="//cdn.test/x">a</a><a href="#top">b</a>'
      .. '<a href="https://ex.test">c</a><a href="/">d</a>'
      .. '<a href="">e</a><div data-href="/hidden/x">f</div>'
      .. '<a href="mailto:a@b.test">g</a>'
  t.keys_eq(linked({ body = { body } }), {})
end)

t.case('linked prefixes skip segments longer than 40 chars', function()
  local long = '/' .. string.rep('a', 41) .. '/x'
  local fits = '/' .. string.rep('b', 40) .. '/x'
  local body = '<a href="' .. long .. '">a</a><a href="' .. fits .. '">b</a>'
  t.keys_eq(linked({ body = { body } }), { '/' .. string.rep('b', 40) })
end)

t.case('linked prefixes are lowercase', function()
  t.keys_eq(linked({ body = { '<a href="/NiFi/x">x</a>' } }), { '/nifi' })
end)

t.case('path_linked matches first segment', function()
  local prefixes = { ['/nacos'] = true }
  t.eq(path_linked('/nacos/v1/cs?x=1', prefixes), true)
  t.eq(path_linked('/nacos', prefixes), true)
end)

t.case('path_linked rejects other paths', function()
  local prefixes = { ['/nacos'] = true }
  t.eq(path_linked('/other/nacos', prefixes), false)
  t.eq(path_linked('/nacosx/y', prefixes), false)
  t.eq(path_linked('/x?nacos', prefixes), false)
  t.eq(path_linked('/', prefixes), false)
end)

t.case('path_linked ignores case', function()
  t.eq(path_linked('/NACOS/v1', { ['/nacos'] = true }), true)
end)
