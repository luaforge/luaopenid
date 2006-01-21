#!/usr/local/bin/lua

--[[
-- Copyright (c) 2006 Keith Howe <nezroy@luaforge.net>
--
-- Permission is hereby granted, free of charge, to any person obtaining a
-- copy of this software and associated documentation files (the "Software"),
-- to deal in the Software without restriction, including without limitation
-- the rights to use, copy, modify, merge, publish, distribute, sublicense,
-- and/or sell copies of the Software, and to permit persons to whom the
-- Software is furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included
-- in all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
-- OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
-- FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
-- DEALINGS IN THE SOFTWARE.
--
--]]

local CGI = require("cgi5")
local url = require("socket.url")
local users = require("users")

function main()
  -- get parameters
  local content = CGI.content() or arg[1]
  local vars = {}
  if content and content ~= "" then
    vars = CGI.vars(content)
  end
  
  -- check for a logout option
  if vars["logout"] then
    print("Set-Cookie: openid_example_user=;")
    auth_user(vars, "You have logged out.")
  -- otherwise, check for an attempted login
  elseif vars["u"] and vars["p"] then
    if not users.is_valid_password(vars["u"], vars["p"]) then
      auth_user(vars, "Login failed: invalid username or password.")
      return
    end
    
    print("Set-Cookie: openid_example_user=" .. vars["u"] .. ";")
    if vars["openid.return_to"] then
      local parsed_identity = url.parse(vars["openid.identity"])
      if parsed_identity.path == users.root .. vars["u"] .. ".html" then
        return_user(vars)
      else
        auth_user(vars, "You are logged in as <strong>" .. vars["u"] .. "</strong>, and do not own this identity.")
      end
    else
      show_user(vars["u"])
    end
  -- otherwise, show the login page or current status
  else
    local userid = users.is_logged_in()
    if userid then
      if vars["openid.return_to"] then
        local parsed_identity = url.parse(vars["openid.identity"])
        if parsed_identity.path == users.root .. userid .. ".html" then
          return_user(vars)
        else
          auth_user(vars, "You are logged in as <strong>" .. userid .. "</strong>, and do not own this identity.")
        end
      else
        show_user(userid)
      end
    else
      auth_user(vars)
    end
  end
end

--[[  auth_user(vars, error_text)

Generates a login page. The vars table contains the parsed CGI parameters, and
the optional error_text contains a status message to display as well.

--]]
function auth_user(vars, error_text)
  -- grab specific openid options we want to preserve
  local openid = {}
  openid["trust_root"] = vars["openid.trust_root"]
  openid["identity"] = vars["openid.identity"]
  openid["return_to"] = vars["openid.return_to"]
  openid["assoc_handle"] = vars["openid.assoc_handle"]
  openid["invalidate_handle"] = vars["openid.invalidate_handle"]
  
  print("Content-Type: text/html; charset=iso-8859-1\n")
  print('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">')
  print("<html><head><title>OpenID example login</title></head><body>")
  
  -- display some useful preamble, depending on how we were called
  if openid.identity and openid.trust_root then
    print("<p><strong>" .. openid.trust_root .. "</strong> is requesting authentication for <strong>" .. openid.identity .. "</strong>.<br>");
    print('Login below, or <a href="' .. openid.return_to .. '&openid.mode=cancel">cancel</a>.<br>')
  else
    print("<p>Use the login form to authenticate.<br>")
  end
  if error_text then
    print(error_text .. "<br>")
  end
  
  -- generate the login form, with preserved values if needed
  print('<form action="' .. users.setup .. '" method="POST">')
  print('User: <input name="u" type="text"><br>')
  print('Password: <input name="p" type="password"><br>')
  print('<input value="login" type="submit">')
  for i, v in pairs(openid) do
    if v then
      print('<input name="openid.' .. i .. '" type="hidden" value="' .. v .. '">')
    end
  end
  print("</form></p></body></html>")
end

--[[  show_user(userid)

Generates a status page for the user that is currently logged in.

--]]
function show_user(userid)
  print("Content-Type: text/html; charset=iso-8859-1\n")
  print('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">')
  print("<html><head><title>OpenID example setup</title></head><body>")
  print('<p>You are logged-in as ' .. userid .. '.')
  print('<form action="' .. users.setup .. '" method="GET">')
  print('<input name="logout" type="hidden" value="1">')
  print('<input value="logout" type="submit">') 
  print("</form></p></body></html>")
end

--[[  return_user(vars)

Generates a redirection page that sends us back through the OpenID server
mechanism, based on the parameters in the vars table. Used when we logged in as
part of an OpenID consumer request, and need to keep the flow moving.

--]]
function return_user(vars)
  local return_to = users.server .. "?openid.mode=checkid_immediate"
  for i, v in ipairs({"return_to", "identity", "trust_root", "assoc_handle", "invalidate_handle"}) do
    local key = "openid." .. v
    if vars[key] then
      return_to = return_to .. "&" .. key .. "=" .. url.escape(vars[key])
    end
  end
  print("Status: 303 See Other")
  print("Location: " .. return_to)
  print("Content-Type: text/html; charset=iso-8859-1\n")
  print(
[[
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
    <title>OpenID redirect</title>
  </head>
  <body>
    <p>You should be redirected automatically. If you did not get redirected, you can follow this link: <a href="]] .. return_to .. '">' .. return_to .. [[</a></p>
  </body>
</html>
]]
  )
end

main()
