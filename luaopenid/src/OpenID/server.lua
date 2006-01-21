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

local string = require("string")
local table = require("table")
local math = require("math")
local io = require("io")
local os = require("os")
local print = print
local ipairs = ipairs
local tostring = tostring
local pairs = pairs
local arg = arg

local CGI = require("cgi5")
local mime = require("mime")
local url = require("socket.url")
local evp = require("crypto.evp")
local hmac = require("crypto.hmac")

module("OpenID.server")

auth_func = nil
setup = nil
srv_secret = nil
adpage = nil
log_path = "server.log"
log_lvl = nil

local sign_list = {"mode", "identity", "return_to"}
local b62 = "abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWZYZ0123456789"
local log_handle = nil

function process_query()
  
  if log_path and log_lvl then
    log_handle = io.open(log_path, "a")
  end
  
  log(3, "--- process_query ---")
  
  if not auth_func or not setup or not srv_secret then
    bad_request("server is not configured")
    return
  end
  
  -- grab input paramters (including command line ones for debugging)
  local content = CGI.content() or arg[1]
  if not content or content == "" then
    if os.getenv("REQUEST_METHOD") == "POST" then
      bad_request("empty content")
    else
      -- someone probably just saw an URL and entered it directly; display an
      -- ad page that tells them what this is all about
      log(3, "dumping adpage")
      if not adpage then
        default_adpage()
      else
        redirect(adpage)
      end
    end
    return
  end
  
  -- get the OpenID parameters we care about
  local vars = CGI.vars(content)
  local openid = {}
  for i, var in ipairs({"mode", "session_type", "assoc_type", "sig", "signed", "identity", "assoc_handle", "return_to", "trust_root", "invalidate_handle"}) do
    openid[var] = vars["openid." .. var]
    log(3, " - openid." .. var .. " = " .. tostring(openid[var]))
  end
  
  -- basically do a switch/case on the mode parameter that was provided
  if not openid.mode then
    bad_request("no openid.mode was provided")
    return
  elseif openid.mode == "associate" then
    associate(openid, vars)
  elseif openid.mode == "checkid_immediate" then
    checkid_immediate(openid, vars)
  elseif openid.mode == "checkid_setup" then
    checkid_setup(openid, vars)
  elseif openid.mode == "check_authentication" then
    check_authentication(openid, vars)
  else
    bad_request(openid.mode .. " is not supported")
    return
  end
  
  if log_handle then log_handle:close() end
  
end

--[[  associate(openid, vars)

This is one of the OpenID mode handlers. The important parameters are in the
openid table, and any extra junk is off in vars. This mode is used to setup a
shared secret between the consumer and the server that can be reused. This
implementation does not support the Diffie-Hellman exchange, so the secret is
sent back in the clear. If the consumer is unhappy about that, they can revert
to "dumb-mode" which does not use shared secrets; this mode is just as secure,
but it has extra overhead and additional transactions.

--]]
function associate(openid, vars)
  local handle = get_assoc_handle(openid)
  local secret = get_assoc_secret(handle)
  
  key_reply{
    assoc_type = "HMAC-SHA1",
    assoc_handle = handle,
    expires_in = 86400,
    session_type = "",
    mac_key = (mime.b64(secret)),
  }
end

--[[  checkid_setup(openid, vars)

This is one of the OpenID mode handlers. The important parameters are in the
openid table, and any extra junk is off in vars. This mode is used when the
consumer wants to check an identity URL and doesn't mind waiting for us to do
some work first, if we need to.

--]]
function checkid_setup(openid, vars)
  local valid, extra = checkid(openid, vars)
  if valid then
    return
  end

  -- send the user agent to the "setup" page to take care of it
  local handle, invalid_handle = get_assoc_handle(openid)
  local setup_params = {
    ["openid.identity"] = openid.identity,
    ["openid.assoc_handle"] = handle,
    ["openid.invalidate_handle"] = invalid_handle,
    ["openid.return_to"] = openid.return_to,
    ["openid.trust_root"] = openid.trust_root,
  }
  if extra then
    for key, value in pairs(extra) do
      setup_params[key] = value
    end
  end
  redirect(setup, setup_params)
end

--[[  checkid_immediate(openid, vars)

This is one of the OpenID mode handlers. The important parameters are in the
openid table, and any extra junk is off in vars. This mode is used when the
consumer wants an immediate response, and is not willing to wait for us to do
any work that might be needed to authenticate the user if they have not already
been authenticated.

--]]
function checkid_immediate(openid, vars)
  local valid, extra = checkid(openid, vars)
  if valid then
    return
  end
  
  -- generate a setup failure assertion
  local handle, invalid_handle = get_assoc_handle(openid)
  local setup_url = setup .. "?openid.identity=" .. url.escape(openid.identity) .. "&openid.return_to=" .. url.escape(openid.return_to) .. "&openid.assoc_handle=" .. url.escape(handle)
  if invalid_handle then
    setup_url = setup_url .. "&openid.invalidate_handle=" .. url.escape(invalid_handle)
  end
  if openid.trust_root then
    setup_url = setup_url .. "&openid.trust_root=" .. url.escape(openid.trust_root)
  end
  if extra then
    for key, value in pairs(extra) do
      setup_url = setup_url .. "&" .. key .. "=" .. url.escape(tostring(value))
    end
  end
  redirect(openid.return_to, {
    ["openid.mode"] = "id_res",
    ["openid.user_setup_url"] = setup_url,
    })
end

--[[  boolean, extra = checkid(openid, vars)

This is a shared handler for both checkid_* mode handlers. It checks if it can
make a positive assertion based on the user currently logged in (if any) and
the identity being authenticated. Returns true if an assertion was made, false
otherwise. Also returns extra setup parameters provided by the auth function.

--]]
function checkid(openid, vars)
  -- check for required parameters
  if not openid.return_to then
    bad_request("openid.return_to is required")
    return false, nil
  end
  if not openid.identity then
    redirect(openid.return_to, {
      ["openid.mode"] = "error",
      ["openid.error"] = "openid.identity is required",
    })
    return false, nil
  end
  
  -- validate the trust_root against the return_to path
  if openid.trust_root then
    local parsed_return = url.parse(openid.return_to)
    local parsed_trust = url.parse(openid.trust_root)
    local passed = false
    if parsed_return.scheme ~= parsed_trust.scheme then
      passed = false
    elseif parsed_return.port ~= parsed_trust.port then
      passed = false
    elseif parsed_trust.path and not string.find(parsed_return.path, "^" .. parsed_trust.path) then
      passed = false
    elseif parsed_trust.host ~= parsed_return.host then
      if string.sub(parsed_trust.host, 1, 1) ~= "*" then
        passed = false
      else
        local trust_host = string.gsub(parsed_trust.host, "%*", "%%w+")
        if not string.find(parsed_return.host, "^" .. trust_host) then
          passed = false
        else
          passed = true
        end
      end
    else
      passed = true
    end
    
    if not passed then
      redirect(openid.return_to, {
        ["openid.mode"] = "error",
        ["openid.error"] = "openid.trust_root is not valid",
      })
      return false
    end
  end
  
  -- check if the user is logged in and matches the identity URL
  local valid, extra = auth_func(url.parse(openid.identity))
  if valid then
    -- generate a positive identity assertion and sign it
    local handle, invalid_handle = get_assoc_handle(openid)
    openid.mode = "id_res"
    redirect(openid.return_to, {
      ["openid.mode"] = "id_res",
      ["openid.identity"] = openid.identity,
      ["openid.assoc_handle"] = handle,
      ["openid.invalidate_handle"] = invalid_handle,
      ["openid.signed"] = get_signed_list(),
      ["openid.return_to"] = openid.return_to,
      ["openid.sig"] = get_signature(openid, handle, sign_list),
    })
    return true, extra
  else
    return false, extra
  end
end

--[[  check_authentication(openid, vars)

This is one of the OpenID mode handlers. The important parameters are in the
openid table, and any extra junk is off in vars. This mode is used to
authenticate an HMAC signature against the stored association.

--]]
function check_authentication(openid, vars)
  local reply = {is_valid = false}
  
  if openid.invalidate_handle and not check_handle(openid.invalidate_handle) then
    reply["invalidate_handle"] = openid.invalidate_handle
  end
  
  if not openid.assoc_handle or not openid.sig or not openid.signed then
    key_reply(reply)
    return
  end
  
  local param_list = split(",", openid.signed)
  for i, param in ipairs(param_list) do
    if not openid[param] then
      key_reply(reply)
      return
    end
  end
  
  if not string.find(openid.assoc_handle, "^%d+:STLS%.") then
    key_reply(reply)
    return
  end
  
  if not check_handle(openid.assoc_handle) then
    key_reply(reply)
    return
  end
  
  openid.mode = "id_res"
  
  local good_sig = get_signature(openid, openid.assoc_handle, param_list)
  if good_sig and good_sig == openid.sig then
    reply["is_valid"] = true
  else
    reply["is_valid"] = false
  end
  
  key_reply(reply)
end

--[[  boolean = check_handle(handle)

Returns whether the provided handle appears to be a good, valid handle or not.

--]]
function check_handle(handle)
  local parts = split(":", handle)
  local check = parts[1] .. ":" .. parts[2] .. ":"
  if parts[3] == string.sub(hmac.digest("sha1", check, srv_secret), 1, 10) then
    return true
  else
    return false
  end
end

--[[  bad_request(error_text)

Dumps a 400 error with the key/value error_text mandated in the spec.

--]]
function bad_request(error_text)
  print("Status: 400 Bad Request")
  print("Content-Type: text/plain\n")
  print(log(1, "error:" .. tostring(error_text)))
end

--[[  redirect(return_url, params)

Redirects the user agent to the location in return_url, tacking on any extra
parameters provided in the params table first. Used all over the place since
much of the OpenID flow is handled through redirects.

--]]
function redirect(return_url, params)
  
  -- parse the URL and tack on extra parameters
  local parsed_return = url.parse(return_url)
  if params then
    local separator = ""
    if (parsed_return.query) then
      separator = parsed_return.query .. "&"
    end
    local new_query = ""
    log(3, "redirect to: " .. return_url)
    for key, value in pairs(params) do
      log(3, " - " .. key .. " = " .. tostring(value))
      new_query = new_query .. separator .. key .. "=" .. url.escape(tostring(value))
      separator = "&"
    end
    parsed_return.query = new_query
  end
  return_url = url.build(parsed_return)
  
  -- generate the redirect page
  print("Status: 303 See Other")
  print(log(2, "Location: " .. tostring(return_url)))
  print("Content-Type: text/html; charset=iso-8859-1\n")
  print(
[[
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
    <title>OpenID redirect</title>
  </head>
  <body>
    <p>You should be redirected automatically. If you did not get redirected, you can follow this link: <a href="]] .. return_url .. '">' .. return_url .. [[</a></p>
  </body>
</html>
]]
  )
  
end

--[[  key_reply(key_table)

Generates a key/value reply document with the parameters provided in the
key_table.

--]]
function key_reply(key_table)
  print("Content-Type: text/plain\n")
  log(3, "sending key reply")
  for key, value in pairs(key_table) do
    log(3, " - " .. key .. " = " .. tostring(value))
    print(string.format("%s:%s", tostring(key), tostring(value)))
  end
end

--[[  signed_list = get_signed_list()

Generates a comma-separated list of fields that will be signed by our HMAC
signature.

--]]
function get_signed_list()
  local separator = ""
  local signed_list = ""
  for i, key in ipairs(sign_list) do
    signed_list = signed_list .. separator .. key
    separator = ","
  end
  return signed_list
end

--[[  assoc_handle = get_assoc_handle(openid)

Generates an assoc_handle based on the parameters provided in the openid table.
Most important is the decision to generate a stateful or stateless handle.

--]]
function get_assoc_handle(openid)
  local mode
  local invalid_handle
  if openid then
    if openid.assoc_handle then
      if check_handle(openid.assoc_handle) then
        log(3, "using valid handle: " .. openid.assoc_handle)
        return openid.assoc_handle
      else
        log(3, "invalidating handle: " .. openid.assoc_handle)
        invalid_handle = openid.assoc_handle
      end
    end
    mode = openid.mode
  end
  
  local nonce = ""
  local now = os.time()
  local handle
  
  math.randomseed(now)
  for i = 1, 20, 1 do
    local digit = math.random(62)
    nonce = nonce .. string.sub(b62, digit, digit)
  end
  if mode ~= "associate" then
    nonce = "STLS." .. nonce
  end
  
  handle = tostring(now) .. ":" .. nonce .. ":"
  handle = handle .. string.sub(hmac.digest("sha1", handle, srv_secret), 1, 10)
  
  log(3, "generated new handle: " .. handle)
  return handle, invalid_handle
end

--[[  assoc_handle = get_assoc_secret(handle)

Generates the shared secret associated with the provided handle.

--]]
function get_assoc_secret(handle)
  local _, _, time, nonce, nonce_sig = string.find(handle, "^(%d+):([%.a-zA-Z0-9]+):([a-zA-Z0-9]+)$")
  
  if not time or not nonce or not nonce_sig then
    return nil
  end
  if nonce_sig ~= string.sub(hmac.digest("sha1", time .. ":" .. nonce .. ":", srv_secret), 1, 10) then
    return nil
  end
  
  return hmac.digest("sha1", handle, srv_secret, true)
end

--[[  signature = get_signature(openid)

Generates an HMAC (SHA1) signature of the relevant parameters in the openid
table, incorporating the shared secret tied to the assoc_handle.

--]]
function get_signature(openid, handle, param_list)
  local secret = get_assoc_secret(handle)
  if not secret then return nil end
  local tokens = ""
  for i, key in ipairs(param_list) do
    tokens = tokens .. key .. ":" .. tostring(openid[key]) .. "\n"
  end
  return (mime.b64(hmac.digest("sha1", tokens, secret, true))) 
end

function split(delimiter, string)
  local parts = {}
  local chomp = string
  local pattern = "^(.-)" .. delimiter
  while chomp ~= "" do
    local _, j, field = string.find(chomp, pattern)
    if j then
      chomp = string.sub(chomp, j + string.len(delimiter), -1)
    else
      field = chomp
      chomp = ""
    end
    table.insert(parts, field)
  end
  
  return parts
end

function default_adpage()
  print "Content-Type: text/html; charset=iso-8859-1\n"
  print([[
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
    <title>OpenID server endpoint</title>
  </head>
  <body>
    <p>This is an OpenID server endpoint. For more information, see <a href="http://openid.net/">http://openid.net/</a></p>
  </body>
</html>
  ]])
end

function log(lvl, message)
  if log_handle and lvl >= log_lvl then
    log_handle:write(os.date())
    log_handle:write(" ")
    log_handle:write(tostring(message))
    log_handle:write("\n")
  end
  
  return message
end
