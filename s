--[[
Keyrblx's official lua-library by sponsoparnordvpn
T0DO :
- Check function integrity 
--]]
--- attacking ---


local old
old = hookfunction(getfenv, function(stack)
    if stack == 1 then
        local fake = {"Environment is protected"}
        return fake
    else
        return old(stack)
    end
end)

-- Secure loadstring 
local function Newlclosure(func)
    if not islclosure(func) then
        return function(...)
            return func(...)
        end
    else
        return func
    end
end

local function Newcclosure(func)
    return coroutine.wrap(function(...)
        while true do
            coroutine.yield(newcclosure(func(...)))
        end
    end)
end

local function clone(func)
    if islclosure(func) then
        return Newlclosure(Newcclosure(func))
    elseif iscclosure(func) then
        return Newcclosure(func)
    end
end

local kloadstring = clone(loadstring)

-- HTTP Tamper Detection
pcall(game.HttpGet, setmetatable({}, {
    __index = function(self, key)
        if debug.getinfo(2).func == game.HttpGet then
            return rawget(self, key)
        else
            while true do end
        end
    end
}))


pcall(request, setmetatable({}, {
    __index = function(self, key)
        if debug.getinfo(2).func == request then
            return rawget(self, key)
        else
            while true do end
        end
    end
}))


local secure_request = function(tbl)
    local Indexes = {'Url', 'Method', 'Headers', 'Cookies', 'Body'}
    local Index_Count = 0

    local SecureMt = setmetatable({
        __index = function(self, key)
            if debug.getinfo(2).func ~= request then
                while true do end
                return
            end
            Index_Count = Index_Count + 1
            if not Indexes[Index_Count] then
                while true do end
                return
            end
            Indexes[Index_Count] = nil
            if key == 'Url' then
                -- Uncomment the line below if needed
                -- return 'https://about:blank'
            end
            return rawget(tbl, key)
        end
    }, {
        __tostring = function()
            while true do end
            return
        end
    })

    local success, result = ypcall(newcclosure(function()
        request(setmetatable({}, SecureMt))
    end))

    if success and result and not result['Headers'] then
        while true do end
        return
    elseif not success then
        error(result)
    end

    return result
end


local secure_httpget = function(url)
    local res = secure_request({
        Url = url,
        Method = "GET"
    })
    return res.Body
end
load = function(path)
	return kloadstring(secure_httpget(path))()
end

local spooftable = function(tbl)
    local oldTbl = tbl
    local newTbl = setmetatable({}, {
        __index = function(_, idx)
            return oldTbl[idx]
        end,
    })
    return newTbl
end

local json = load("https://keyrblx.com/library/json.lua")

local JSONDecode = function(...)
    local result = json.decode(...)
    local proxy = setmetatable(result, {
        __index = function(self, key)
        if (debug.getinfo(2).func ~= json.decode) then
        warn("Fatal error occured !")
        return
	    end
            return rawget(self, key)
        end,
        __newindex = function(_, key, value)
            error("Attempt to modify read-only  result", 2)
        end,
        __metatable = false
    })
    return proxy
end



local function BitXOR(a, b)
    local p, c = 1, 0
    while a > 0 and b > 0 do
        local ra, rb = a % 2, b % 2
        if ra ~= rb then
            c = c + p
        end
        a, b, p = (a - ra) / 2, (b - rb) / 2, p * 2
    end
    if a < b then
        a = b
    end
    while a > 0 do
        local ra = a % 2
        if ra > 0 then
            c = c + p
        end
        a, p = (a - ra) / 2, p * 2
    end
    return c
end

local function dec2Hex(val)
    if val >= 0 and val < 16 then
        return string.format("0%X", tonumber(val))
    elseif val > 15 and val < 128 then
        return string.format("%X", tonumber(val))
    elseif val == 0 then
        return "00"
    elseif val < 0 and val > -128 then
        return string.sub(string.format("%X", tostring(val)), 15)
    end
end

XOR_Encode = function(sentString, sentKey, customSpace)
    local Answer = {}
    local Keys = {}
    local KeyIndex = 1
    for c in sentKey:gmatch"." do
        table.insert(Keys, string.byte(c))
    end
    for c in sentString:gmatch"." do
        local key = Keys[KeyIndex]
        KeyIndex = Keys[KeyIndex + 1] and KeyIndex + 1 or 1
        table.insert(Answer, dec2Hex(BitXOR(string.byte(c), key)))
    end
    return Answer, table.concat(Answer, customSpace or " ")
end
local xorhold = {}
xorhold["XOR_Decode\0"] = function(sentData, sentKey, customSpace)
    local Answer = {}
    local Keys = {}
    local KeyIndex = 1
    for c in sentKey:gmatch"." do
        table.insert(Keys, string.byte(c))
    end
    if type(sentData) == "string" then
        for c in (sentData .. (customSpace or " ")):gmatch("(.-)" .. (customSpace or " ")) do
            local key = Keys[KeyIndex]
            KeyIndex = Keys[KeyIndex + 1] and KeyIndex + 1 or 1
            table.insert(Answer, string.char(BitXOR(tonumber(c, 16), key)))
        end
    else
        for i, c in ipairs(sentData) do
            local key = Keys[KeyIndex]
            KeyIndex = Keys[KeyIndex + 1] and KeyIndex + 1 or 1
            table.insert(Answer, string.char(BitXOR(tonumber(c, 16), key)))
        end
    end
    return Answer, table.concat(Answer, "")
end

getgenv().setclipboard = setclipboard or toclipboard or set_clipboard or (Clipboard and Clipboard.set)

local get_client_id = function()
local clientId

if identifyexecutor and 'Delta, Android' == identifyexecutor() then
    clientId = gethwid()
else
	clientId = game:GetService("RbxAnalyticsService"):GetClientId()
end

clientId = string.gsub(clientId, "-", "")
return clientId
end
local hashIP
local getHwid =  function(hwidType)
	if hwidType == nil then
		return clientId
	end

	if type(hwidType) == "string" then
		local hwidType = string.lower(hwidType)
		if hwidType == "ip" then
			if not hashIP then
				hashIP = game:HttpGet("https://api.keyrblx.com/utils/get_ip_hash")
			end
			return hashIP
		elseif hwidType == "clientid" then
			return get_client_id()
		end
	end
end


local data = JSONDecode(
	secure_httpget("https://raw.githubusercontent.com/MaGiXxScripter0/keysystemv2api/master/data.json")
)
local HashLibrary = load("https://keyrblx.com/library/hashlib.lua")
local __SECRET_KEY = "981523495843963209324"
local __SECRET_DEFAULT_KEY = "17826318276412637812"
local __SECRET_PREMIUM_KEY = "1297319287472165312"

-- ServiceAPI

local ServiceAPI = {}
local self = {}


ServiceAPI["Set\0"] = function(settings)

    self.application = settings.ApplicationName 
    self.authtype = settings.AuthType 
    self.key = settings.EncryptionKey 
    self.truedata = settings.TrueData 
    self.falsedata = settings.FalseData
    self.debug = settings.Debug or false

    warn("=======================================")
    warn("Welcome to keyrblx !")
    warn("Library Version: " .. (getgenv().LibVersion or "2.0.0"))
    warn("Executor : " .. tostring(identifyexecutor()))
    warn("Status : online")
    warn("=======================================")
end
self.Debug = function(self,message)
    if self.debug then
        warn("[DEBUG] ", message)
    end
end
ServiceAPI["GetKey\0"] = function()
    local hwid = getHwid(self.authtype)
    self:Debug("Your current HWID : " .. hwid)
    local url = data.url_root .. "/getkey/" .. self.application .. "?hwid=" .. hwid
    return url
end

ServiceAPI["VerifyPremiumKey\0"] = function(keyString)
    local hwid = getHwid(self.authtype)
    self:Debug("Your current HWID : " .. hwid)
    self:Debug("User key : " .. keyString)
    self:Debug("Application : " .. self.application)

    local result
    result = secure_httpget(
        data.api_url
            .. "/key/premium_key_protected?key="
            .. keyString
            .. "&name="
            .. self.application
            .. "&hwid="
            .. hwid
    )
   if result == '{"detail":"Not Found"}' then
    local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.falsedata .. "&type=sha1")
    local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
    return encodedData
end

    self:Debug("Hashed result : " .. result)
    local mixed = keyString .. hwid
    local hash = HashLibrary.hmac(HashLibrary.sha512,__SECRET_PREMIUM_KEY,mixed)

    if hash == result then
        local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.truedata .. "&type=sha1")
        local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
        return encodedData
    else
        local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.falsedata .. "&type=sha1")
        local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
        return encodedData
    end
end

ServiceAPI["VerifyDefaultKey\0"] = function(keyString)
    local hwid = getHwid(self.authtype)
    self:Debug("Your current HWID : " .. hwid)
    self:Debug("User key : " .. keyString)
    self:Debug("Application : " .. self.application)

    local result
    result = secure_httpget(
        data.api_url
            .. "/key/default_key_protected?key="
            .. keyString
            .. "&name="
            .. self.application
            .. "&hwid="
            .. hwid
    )
    if result == '{"detail":"Not Found"}' then
    local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.falsedata .. "&type=sha1")
    local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
    return encodedData
end

    self:Debug("Hashed result : " .. result)
    local mixed = keyString .. hwid
    local key = __SECRET_DEFAULT_KEY
    local hash = HashLibrary.hmac(HashLibrary.sha512,key,mixed)
    
    if hash == result then
        local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.truedata .. "&type=sha1")
        local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
        return encodedData
    else
        local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.falsedata .. "&type=sha1")
        local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
        return encodedData
    end
end

ServiceAPI["VerifyKey\0"] = function(keyString)
    local hwid = getHwid(self.authtype)
    self:Debug("Your current HWID : " .. hwid)
    self:Debug("User key : " .. keyString)
    self:Debug("Application : " .. self.application)

    local result
    result = secure_httpget(
        data.api_url
            .. "/key/protected?key="
            .. keyString
            .. "&name="
            .. self.application
            .. "&hwid="
            .. hwid
    )
    if result == '{"detail":"Not Found"}' then
    local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.falsedata .. "&type=sha1")
    local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
    return encodedData
end

    self:Debug("Hashed result : " .. result)
    local mixed = keyString .. hwid
    local key = __SECRET_KEY
    local hash = HashLibrary.hmac(HashLibrary.sha512,key,mixed)
    warn(hash)
    if hash == result then
        local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.truedata .. "&type=sha1")
        local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
        return encodedData
    else
        local new_hashed = secure_httpget("https://api.keyrblx.com/utils/hashlib?text=" .. self.falsedata .. "&type=sha1")
        local encodedData, encodedString = XOR_Encode(new_hashed, self.key, "-")
        return encodedData
    end
end

ServiceAPI["GetPremiumKeyData\0"] = function(key)
local hwid = getHwid(self.authtype)
local url = data.api_url .. "/premium_key/me?name=" .. self.application .. "&key=" .. key .. "&hwid=" .. hwid
return JSONDecode(secure_httpget(url))
end

ServiceAPI["GetKeyData\0"] = function(key)
local hwid = getHwid(self.authtype)
local url = data.api_url .. "/key/me?name=" .. self.application .. "&key=" .. key .. "&hwid=" .. hwid
return JSONDecode(secure_httpget(url))
end

ServiceAPI["GetApplicationData\0"] = function()
return JSONDecode(secure_httpget("https://api.keyrblx.com/api/application/get?name="..self.application))
end

local KeyLibrary = {}
KeyLibrary.Set = ServiceAPI["Set\0"]
KeyLibrary.GetKey = ServiceAPI["GetKey\0"]
KeyLibrary.VerifyPremiumKey = ServiceAPI["VerifyPremiumKey\0"]
KeyLibrary.VerifyDefaultKey = ServiceAPI["VerifyDefaultKey\0"]
KeyLibrary.VerifyKey = ServiceAPI["VerifyKey\0"]
KeyLibrary.GetPremiumKeyData = ServiceAPI["GetPremiumKeyData\0"]
KeyLibrary.GetKeyData = ServiceAPI["GetKeyData\0"]
KeyLibrary.GetApplicationData = ServiceAPI["GetApplicationData\0"]
KeyLibrary.XORDecode = function(encoded)
return xorhold["XOR_Decode\0"](encoded,self.key)
end

setmetatable(KeyLibrary, {
		__index = function(self, key)
			return rawget(self, key)
		end,
		__newindex = function(self, key, value)
			if getfenv(2) ~= value then
				error("This metatable is protected", 2)
			end
			rawset(self, key, value)
		end,
		__metatable = "This metatable is protected."
	})

local HashLibrary = loadstring(game:HttpGet("https://raw.githubusercontent.com/Egor-Skriptunoff/pure_lua_SHA/master/sha2.lua"))()
local KeyLibrary = KeyLibrary or loadstring(game:HttpGet("https://raw.githubusercontent.com/MaGiXxScripter0/keysystemv2api/master/version2.lua"))()

KeyLibrary.Set({
    ApplicationName = "RaitoHub",
    AuthType = "clientid",
    EncryptionKey = "any data",
    TrueData = "YourTrueData",
    FalseData = "YourFalseData",
})

local o_data = KeyLibrary.VerifyKey("keystring") or KeyLibrary.VerifyPremiumKey("keystring") or KeyLibrary.VerifyDefaultKey("keystring")

local _, decrypted_data = KeyLibrary.XORDecode(o_data)

local true_ = HashLibrary.sha1("YourTrueData")
local false_ = HashLibrary.sha1("YourFalseData")

if true_ == decrypted_data then
    warn("Key is a valid key !")
elseif false_ == decrypted_data then
    warn("Key is non-valid !")
else
    warn("decrypt error")
end
