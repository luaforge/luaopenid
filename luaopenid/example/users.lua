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

local tostring = tostring
local string = string
local os = os

module("users")

-- configuration settings
domain = "openid.example.com"
root = "/" -- include trailing (and leading) slash!
setup = "http://" .. domain .. root .. "setup.cgi"
server = "http://" .. domain .. root .. "server.cgi"

-- the user/password table
local user_table = {
  alice = "apple",
  bob = "banana",
}

--[[  bool = is_valid_password(user, password)

Returns a boolean indicating if the user and password provided match the
stored password for the user.

--]]
function is_valid_password(user, password)
  if user_table[user] and user_table[user] == password then
    return true
  else
    return false
  end
end

--[[  bool = is_logged_in()

Checks the session cookie to see if the user is logged in and valid.

--]]
function is_logged_in()
  local _, _, user = string.find(tostring(os.getenv("HTTP_COOKIE")), "openid_example_user=(%w+)")
  if user and user_table[user] then
    return user
  else
    return nil
  end
end

--[[  bool, extra = auth_function(identity)

Takes the parsed identity URL table and checks if there is a current user
logged in and whether that user owns this identity.

--]]
function auth_function(identity)
  if identity.host ~= domain then
    return false, nil
  end

  local _, _, userid = string.find(identity.path, "^" .. root .. "(%w+)%.html$")  
  if userid and userid == is_logged_in() then
    return true, nil
  end

  return false, nil
end
