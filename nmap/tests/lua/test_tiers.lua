-- SPDX-License-Identifier: GPL-3.0-or-later
-- Sweep tier classification and path grouping.

local t = require 'harness'
t.load_scanner()
local tiers = require 'cvescannerv2.catalog.tiers'

t.suite('sweep tiers')

t.case('CORE lists the 16 paths in request order', function()
  t.eq(tiers.CORE, {
    '/robots.txt', '/login', '/admin', '/admin/', '/api', '/api/',
    '/version', '/api/v1/version', '/manifest.json', '/healthz',
    '/metrics', '/index.html', '/health', '/info', '/console',
    '/readme.txt',
  })
end)

t.case('core paths classify as core', function()
  for _, path in ipairs(tiers.CORE) do
    t.eq(tiers.classify(path), 'core', path)
  end
end)

t.case('wordpress paths classify by prefix or fragment', function()
  t.eq(tiers.classify('/wp-content/plugins/x/readme.txt'),
    'family:wordpress')
  t.eq(tiers.classify('/wp-login.php'), 'family:wordpress')
  t.eq(tiers.classify('/blog/wp-includes/js/x.js'), 'family:wordpress')
  t.eq(tiers.classify('/x/wp-admin/index.html'), 'family:wordpress')
end)

t.case('domino paths classify by nsf extension or inotes prefix', function()
  t.eq(tiers.classify('/mail/box.nsf'), 'family:domino')
  t.eq(tiers.classify('/iNotes/x.html'), 'family:domino')
end)

t.case('coldfusion paths classify by cfm extension', function()
  t.eq(tiers.classify('/app/index.cfm'), 'family:coldfusion')
end)

t.case('aspnet paths classify by asp family extensions', function()
  t.eq(tiers.classify('/a.asp'), 'family:aspnet')
  t.eq(tiers.classify('/a.aspx'), 'family:aspnet')
  t.eq(tiers.classify('/a.axd'), 'family:aspnet')
  t.eq(tiers.classify('/a.asmx'), 'family:aspnet')
  t.eq(tiers.classify('/a.ashx'), 'family:aspnet')
end)

t.case('java paths classify by java family extensions', function()
  t.eq(tiers.classify('/a.jsp'), 'family:java')
  t.eq(tiers.classify('/a.jhtml'), 'family:java')
  t.eq(tiers.classify('/a.jsa'), 'family:java')
  t.eq(tiers.classify('/a.do'), 'family:java')
  t.eq(tiers.classify('/a.action'), 'family:java')
end)

t.case('cgi paths classify by prefix or cgi family extensions', function()
  t.eq(tiers.classify('/cgi-bin/test'), 'family:cgi')
  t.eq(tiers.classify('/a.cgi'), 'family:cgi')
  t.eq(tiers.classify('/a.pl'), 'family:cgi')
  t.eq(tiers.classify('/a.shtml'), 'family:cgi')
end)

t.case('php paths classify by php extension', function()
  t.eq(tiers.classify('/a.php'), 'family:php')
end)

t.case('query and fragment are ignored when classifying', function()
  t.eq(tiers.classify('/a.php?x=1'), 'family:php')
  t.eq(tiers.classify('/a.php#frag'), 'family:php')
  t.eq(tiers.classify('/login?next=/x'), 'core')
  t.eq(tiers.classify('/about.html?x'), 'tail')
end)

t.case('root and unknown paths are tail', function()
  t.eq(tiers.classify('/'), 'tail')
  t.eq(tiers.classify('/about.html'), 'tail')
  t.eq(tiers.classify('/static/logo.png'), 'tail')
end)

t.case('a directory named like an extension is not a family', function()
  t.eq(tiers.classify('/a.php/'), 'tail')
end)

t.case('build places core paths present in the input in CORE order', function()
  local result = tiers.build({ '/healthz', '/x.txt', '/login', '/' })
  t.eq(result.core, { '/login', '/healthz' })
end)

t.case('build omits core paths absent from the input', function()
  local result = tiers.build({ '/a.php' })
  t.eq(result.core, {})
end)

t.case('build groups families with original order', function()
  local result = tiers.build({
    '/b.php', '/wp-login.php', '/c.php', '/d.aspx',
  })
  t.eq(result.families.php, { '/b.php', '/c.php' })
  t.eq(result.families.wordpress, { '/wp-login.php' })
  t.eq(result.families.aspnet, { '/d.aspx' })
  t.keys_eq(result.families, { 'php', 'wordpress', 'aspnet' })
end)

t.case('build keeps tail paths in original order', function()
  local result = tiers.build({ '/z.html', '/a.php', '/y.html', '/' })
  t.eq(result.tail, { '/z.html', '/y.html', '/' })
end)

t.case('build removes duplicate paths', function()
  local result = tiers.build({ '/a.php', '/a.php', '/', '/', '/login',
    '/login' })
  t.eq(result.families.php, { '/a.php' })
  t.eq(result.tail, { '/' })
  t.eq(result.core, { '/login' })
end)

t.case('build of an empty list gives empty tiers', function()
  local result = tiers.build({})
  t.eq(result.core, {})
  t.eq(result.tail, {})
  t.keys_eq(result.families, {})
end)

t.case('overlay path appended last stays last within php', function()
  local base = { '/a.php', '/b.php' }
  local overlay = { '/a.php', '/b.php', '/new.php' }
  local result = tiers.build(overlay)
  t.eq(result.families.php, { '/a.php', '/b.php', '/new.php' })
  t.eq(result.families.php[#result.families.php], '/new.php')
  t.eq(#tiers.build(base).families.php, 2)
end)
