--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are met:
--   1. Redistributions of source code must retain the above copyright notice,
-- this list of conditions and the following disclaimer.
--   2. Redistributions in binary form must reproduce the above copyright
-- notice, this list of conditions and the following disclaimer in the
-- documentation and/or other materials provided with the distribution.
--   3. The name of the author may not be used to endorse or promote products
-- derived from this software without specific prior written permission.

-- This software is provided as-is; all express or implied warranties are
-- disclaimed, just like the all-caps section in the BSD license.
--
-- 17 May 2005: changes to fix bugs submitted by Robert Weiss
-- 03 Jan 2006: updated to 5.1 module format


-- This is a module conformant to LTN 07. 
-- http://www.lua.org/notes/ltn007.html

-- Usage:
-- local CGI = require("cgi5")
-- content = CGI.content()
-- CGI.content() only works the first time you call it. content is the GET and
-- POST (if any) content, URL-encoded.
--
-- vars = CGI.vars(content)
-- vars is a table whose keys are the form variable names, and whose values 
-- are their values.
--
-- unenc = CGI.de_url_encode(enc)
-- enc is a string containing + for spaces, and %xx hex codes. unenc is the
-- unencoded equivalent.
--
-- You're on your own for replying based on the variables you find: note
-- especially that cgi.lua does not print HTTP headers for you.

local string = require("string")
local table = require("table")
local os = require("os")
local io = require("io")
local tonumber = tonumber
module("cgi5")

function content()
  if(os.getenv("REQUEST_METHOD") == "POST") then
    local clength = tonumber(os.getenv("CONTENT_LENGTH"))
    local content = io.read(clength)
    local getcontent = os.getenv("QUERY_STRING")
    if(getcontent ~= "") then
      content = content .. "&" .. getcontent
    end
    return content
  else
    return os.getenv("QUERY_STRING")
  end
end

local function hex_to_ch(str)
  return string.char(tonumber(str, 16))
end

local function split(str, delim)
  local result = {}
  local right = str
  local left
  local dloc = string.find(str, delim, 1, 1)
  while(dloc) do
    left = string.sub(str,1,dloc-1)
    right = string.sub(str,dloc+1)
    table.insert(result, left)
    str = right
    dloc = string.find(str, delim, 1, 1)
  end
  table.insert(result, right)
  return result
end

function de_url_encode(str)
  return string.gsub(string.gsub(str, "%+", " "), "%%(%x%x)", hex_to_ch)
end

function vars(content)
  local result = {}
  local vars = split(content, "&")
  for i = 1, table.getn(vars) do
    local v = vars[i]
    local t = split(v, "=")
    if table.getn(t) > 1 then 
      name, value = t[1], t[2]
      value = de_url_encode(value)
    else
      name, value = t[1], 1
    end
    name = de_url_encode(name)
    result[name] = value
  end
  return result
end
