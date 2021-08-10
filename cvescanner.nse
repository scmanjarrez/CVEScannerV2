description = [[
Search for vulnerabilities analyzing open ports. CVEs information gathered from nvd.nist.gov.
]]
--- Prerequisite: Download Databases
-- @usage ./databases.py

--- Execute CVEscanner
-- @usage nmap -sV <target-ip> --script=./cvescanner.nse
--
-- @output
-- PORT      STATE SERVICE       VERSION
-- 3306/tcp  open  mysql         MySQL 5.5.23
-- | cvescanner:
-- |   product: MYSQL
-- |   version: 5.5.23
-- |   n_vulnerabilities: X
-- |   vulnerabilities:
-- |     CVE ID           CVSSv2   CVSSv3   Exploits
-- |     CVE-2019-13401   6.8      8.8      No
-- |     CVE-2019-13402   6.5      8.8      No
-- |     CVE-2019-13400   5.0      9.8      Yes
-- |     CVE-2019-13403   5.0      7.5      Yes
-- |     CVE-2015-4651    5.0      -        Yes
-- |     ...
---

categories = {"discovery", "version", "safe"}

author = "Sergio Chica"


local nmap = require "nmap"
local stdnse = require "stdnse"
local sql = require "luasql.sqlite3"

local DB = 'cve.db'

env = sql.sqlite3()
conn = env:connect(DB)

-- Returns true for every host-port open
portrule = function(host, port)
   return port.service ~= "tcpwrapped" and
      port.service ~= "unknown" and
      port.version.product ~= nil and
      port.version.version ~= nil
end

postrule = function () return true end

function check_db()
   local db = io.open(DB, "r")
   return db ~= nil and io.close(db)
end


local function vulnerabilities(product, version)
   -- Query CVE, CVSSv2 and CVSSv3 by product and version
   local cur = conn:execute(
      string.format(
         [[SELECT Affected.CVE, CVEs.CVSSV2, CVEs.CVSSV3, (SELECT EXISTS (SELECT 1 FROM Referenced WHERE CVE = Affected.CVE)) as Exploits
           FROM Products
           INNER JOIN Affected ON Products.ProductID = Affected.ProductID
           INNER JOIN CVEs ON Affected.CVE = CVEs.CVE
           WHERE Products.Product = "%s" AND Products.Version = "%s";]],
           product, version)
   )
   local vulns = {}
   local vuln, cvssv2, cvssv3, exploits = cur:fetch()
   while vuln do
      vulns[vuln] = {CVSSV2 = cvssv2, CVSSV3 = cvssv3, Exploits = exploits}
      vuln, cvssv2, cvssv3, exploits = cur:fetch()
   end

   -- Sort CVEs by CVSSv2
   local sorted = {}
   for key, value in pairs(vulns) do
      table.insert(sorted, {key, value.CVSSV2, value.CVSSV3, value.Exploits})
   end
   table.sort(sorted, function(a, b) return a[2] > b[2] end)

   -- Pretty print the output
   local output = {}
   table.insert(output,
                string.format(
                   "%-15s\t%-5s\t%-5s\t%-10s",
                   "CVE ID", "CVSSv2", "CVSSv3", "Exploits"
                )
   )
   for _, value in ipairs(sorted) do
      print(value[4])
      table.insert(output,
                   string.format(
                      "%-15s\t%-5s\t%-5s\t%-10s",
                      value[1], value[2],
                      value[3] and value[3] or "-",
                      value[4] == 1 and "Yes" or "No"
                   )
      )
   end

   cur:close()
   return output
end

function portaction (host, port)
   if check_db() then
      local product = string.lower(port.version.product)
      local version = port.version.version

      stdnse.verbose(2, "[QUERY] product: %s | version: %s", product, version)
      local vulns = vulnerabilities(product, version)
      -- local vulns = vulnerabilities("tenshi", "0.15")
      if #vulns > 1 then
         return vulns
      end
   else
      stdnse.verbose(1, "Database not found. Run ./databases.py before running nmap script.")
   end
end

function postaction ()
        conn:close()
        env:close()
end

local ActionsTable = {
  portrule = portaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
