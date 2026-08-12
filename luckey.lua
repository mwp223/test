-- key-bypasser.lua
-- Universal key/auth bypasser for Roblox script protectors.
-- Paste this ABOVE the protected script (or loadstring call) in your executor.
--
-- Hooks HTTP validation, loadstring gates, Player:Kick(), and periodic
-- re-validation loops so the script loads AND stays running.

-- ═══════════════════════════════════════════════════════════════
--  Config
-- ═══════════════════════════════════════════════════════════════

local DUMP_PAYLOADS = true
local OUT_FILE      = "keybypassed_dump.lua"
local FAKE_HWID     = "BYPASSED-0000-0000-0000-000000000000"

-- ═══════════════════════════════════════════════════════════════
--  Internals
-- ═══════════════════════════════════════════════════════════════

local __cc  = newcclosure or function(f) return f end
local __hf  = hookfunction or replaceclosure
local __hm  = hookmetamethod
local __env = (type(getgenv) == "function" and getgenv()) or _G

local captures, captureCount = {}, 0

local function log(...)
    if type(print) == "function" then print("[key-bypass]", ...) end
end

local function save(content)
    if type(setclipboard) == "function" then pcall(setclipboard, content) end
    if type(writefile) == "function" then pcall(writefile, OUT_FILE, content) end
end

local function encode(s)
    if s:sub(1, 1) == "\27" then
        local hex = {}
        for i = 1, #s do hex[i] = string.format("%02X", s:byte(i)) end
        return "[[BINARY BYTECODE, hex]]\n" .. table.concat(hex)
    end
    return s
end

-- ═══════════════════════════════════════════════════════════════
--  Key URL detection
-- ═══════════════════════════════════════════════════════════════

local KEY_DOMAINS = {
    "getpolsec.com", "api.polsec",
    "luarmor.net", "api.luarmor",
    "keyauth.win", "api.keyauth",
    "api.scriptware", "auth.scriptware",
    "api.myexploit",
    "linkvertise.com", "link-to.net", "direct-link.net",
    "gateway.platoboost.com",
    "flux.li",
    "getkey", "validate", "checkkey", "verify",
    "whitelist", "license", "authenticate", "hwid",
}

local function isKeyUrl(url)
    if type(url) ~= "string" then return false end
    local lower = url:lower()
    for _, p in ipairs(KEY_DOMAINS) do
        if lower:find(p, 1, true) then return true end
    end
    return false
end

-- ═══════════════════════════════════════════════════════════════
--  Spoofed HTTP responses
-- ═══════════════════════════════════════════════════════════════

local function fakeResponse(url)
    local lower = (type(url) == "string" and url:lower()) or ""
    local body

    if lower:find("polsec") then
        body = '{"success":true,"message":"Valid key","script":"","hwid":"' .. FAKE_HWID .. '"}'
    elseif lower:find("luarmor") then
        body = '{"success":true,"message":"Authorized","paid":true,"response":"Whitelisted"}'
    elseif lower:find("keyauth") then
        body = '{"success":true,"message":"Logged in!","info":{"username":"bypass","subscriptions":[{"subscription":"default","expiry":"9999999999","timeleft":999999}]}}'
    else
        body = '{"success":true,"valid":true,"message":"OK","whitelisted":true,"hwid":"' .. FAKE_HWID .. '"}'
    end

    return {
        StatusCode = 200, StatusMessage = "OK", Success = true,
        Headers = { ["Content-Type"] = "application/json" },
        Body = body,
    }
end

-- ═══════════════════════════════════════════════════════════════
--  1) Hook: HTTP request functions
-- ═══════════════════════════════════════════════════════════════

local function hookHttp(name, original)
    if type(original) ~= "function" then return end
    local real = original

    local wrapped = __cc(function(opts, ...)
        local url = opts
        if type(opts) == "table" then url = opts.Url or opts.url or opts.URL or "" end
        if type(url) ~= "string" then url = tostring(url) end

        if isKeyUrl(url) then
            log("HTTP INTERCEPT: " .. url)
            return fakeResponse(url)
        end
        return real(opts, ...)
    end)

    if type(__hf) == "function" then
        local ok, tramp = pcall(__hf, original, wrapped)
        if ok and type(tramp) == "function" then real = tramp end
    else
        __env[name] = wrapped
    end
    log("hooked " .. name)
end

local httpTargets = { { "request", request }, { "http_request", http_request } }
if type(syn) == "table" and syn.request then table.insert(httpTargets, { "syn.request", syn.request }) end
if type(http) == "table" and http.request then table.insert(httpTargets, { "http.request", http.request }) end
if type(fluxus) == "table" and fluxus.request then table.insert(httpTargets, { "fluxus.request", fluxus.request }) end

for _, e in ipairs(httpTargets) do pcall(hookHttp, e[1], e[2]) end

-- ═══════════════════════════════════════════════════════════════
--  2) Hook: __namecall (HttpGet, Kick, Destroy on key UIs)
-- ═══════════════════════════════════════════════════════════════

if type(__hm) == "function" then
    local interceptMethods = {
        HttpGet = true, HttpGetAsync = true, GetObjects = true,
        Kick = true,
    }

    local oldNamecall
    oldNamecall = __hm(game, "__namecall", __cc(function(self, ...)
        local method = getnamecallmethod()

        if not interceptMethods[method] then
            return oldNamecall(self, ...)
        end

        -- Block Player:Kick()
        if method == "Kick" then
            if typeof(self) == "Instance" and self:IsA("Player") then
                log("BLOCKED Kick: " .. tostring(select(1, ...) or "no reason"))
                return
            end
            return oldNamecall(self, ...)
        end

        -- Intercept HttpGet/HttpGetAsync
        if method == "HttpGet" or method == "HttpGetAsync" then
            local url = select(1, ...)
            if type(url) == "string" and isKeyUrl(url) then
                log("NAMECALL INTERCEPT " .. method .. ": " .. url)
                return fakeResponse(url).Body
            end
            return oldNamecall(self, ...)
        end

        -- Intercept GetObjects
        if method == "GetObjects" then
            local url = select(1, ...)
            if type(url) == "string" and isKeyUrl(url) then
                log("NAMECALL INTERCEPT GetObjects: " .. url)
                return {}
            end
            return oldNamecall(self, ...)
        end

        return oldNamecall(self, ...)
    end))
    log("hooked __namecall")
end

-- ═══════════════════════════════════════════════════════════════
--  3) Hook: loadstring / load (capture + execute)
-- ═══════════════════════════════════════════════════════════════

local function hookLoadstring(name, original)
    if type(original) ~= "function" then return end
    local real = original

    local wrapped = __cc(function(src, ...)
        if type(src) == "string" and #src > 100 then
            captureCount += 1
            log("loadstring layer " .. captureCount .. " (" .. #src .. " bytes)")
            if DUMP_PAYLOADS then
                captures[#captures + 1] =
                    "--[[ " .. name .. " layer " .. captureCount ..
                    " (" .. #src .. " bytes) ]]\n" .. encode(src)
                save(table.concat(captures, "\n\n--[[ ===== LAYER BOUNDARY ===== ]]\n\n"))
            end
        end
        return real(src, ...)
    end)

    if type(__hf) == "function" then
        local ok, tramp = pcall(__hf, original, wrapped)
        if ok and type(tramp) == "function" then
            real = tramp
        elseif not ok then
            __env[name] = wrapped
        end
    else
        __env[name] = wrapped
        if name == "loadstring" then loadstring = wrapped end
    end
    log("hooked " .. name)
end

local __ls0 = loadstring or load
hookLoadstring("loadstring", __ls0)
if load and load ~= __ls0 then hookLoadstring("load", load) end

-- ═══════════════════════════════════════════════════════════════
--  4) Hook: error() — suppress key/auth errors only
--     Lightweight: one string check, no table/loop
-- ═══════════════════════════════════════════════════════════════

if type(__hf) == "function" then
    pcall(function()
        local realError = error
        local tramp
        tramp = __hf(error, __cc(function(msg, ...)
            if type(msg) == "string" then
                local l = msg:lower()
                if l:find("key") or l:find("license") or l:find("whitelist")
                    or l:find("not authorized") or l:find("invalid") and l:find("auth")
                    or l:find("expired") or l:find("hwid") or l:find("no key") then
                    log("SUPPRESSED error: " .. msg)
                    return
                end
            end
            return (tramp or realError)(msg, ...)
        end))
        log("hooked error()")
    end)
end

-- ═══════════════════════════════════════════════════════════════
--  5) Hook: HWID spoofing
-- ═══════════════════════════════════════════════════════════════

if type(__hf) == "function" then
    if type(gethwid) == "function" then
        pcall(function() __hf(gethwid, __cc(function() return FAKE_HWID end)) end)
        log("spoofed gethwid")
    end
    if type(getexecutorname) == "function" then
        pcall(function() __hf(getexecutorname, __cc(function() return "Wave" end)) end)
        log("spoofed executor name")
    end
end

-- ═══════════════════════════════════════════════════════════════
--  6) Anti-kick: block common kick/disconnect patterns
-- ═══════════════════════════════════════════════════════════════

local Players = game:GetService("Players")
local player = Players.LocalPlayer

-- Block teleport-as-kick
pcall(function()
    local TeleportService = game:GetService("TeleportService")
    local realTeleport = TeleportService.Teleport
    if type(__hf) == "function" and type(realTeleport) == "function" then
        local tramp
        tramp = __hf(realTeleport, __cc(function(self, placeId, ...)
            if placeId == 0 or placeId == nil then
                log("BLOCKED teleport kick")
                return
            end
            return (tramp or realTeleport)(self, placeId, ...)
        end))
        log("hooked TeleportService:Teleport")
    end
end)

-- Kill any ScreenGuis named after key systems that pop up late
if player then
    local pg = player:FindFirstChild("PlayerGui")
    if pg then
        pg.ChildAdded:Connect(function(child)
            task.defer(function()
                if not child or not child.Parent then return end
                local name = child.Name:lower()
                if name:find("key") or name:find("auth") or name:find("license")
                    or name:find("whitelist") or name:find("polsec")
                    or name:find("luarmor") then
                    log("destroyed key UI: " .. child.Name)
                    child:Destroy()
                end
            end)
        end)
        log("monitoring PlayerGui")
    end
end

-- ═══════════════════════════════════════════════════════════════
--  7) Periodic bypass refresh — re-set auth globals every 10s
--     Catches scripts that clear auth flags on a timer
-- ═══════════════════════════════════════════════════════════════

task.spawn(function()
    while task.wait(10) do
        for _, name in ipairs({
            "Authenticated", "authenticated", "AUTHENTICATED",
            "KeyValid", "keyValid", "keyvalid",
            "Whitelisted", "whitelisted", "WHITELISTED",
            "IsAuthed", "isAuthed", "authed",
            "Verified", "verified", "VERIFIED",
            "Licensed", "licensed",
            "_keyOk", "_authed", "_verified",
        }) do
            pcall(function()
                if __env[name] ~= nil then
                    __env[name] = true
                end
            end)
        end
    end
end)
log("auth flag refresh loop started (10s)")

-- ═══════════════════════════════════════════════════════════════
--  Ready
-- ═══════════════════════════════════════════════════════════════

log("══════════════════════════════════════")
log("  Key Bypasser v2 loaded")
log("  HTTP intercept:  ON")
log("  Kick blocker:    ON")
log("  Error suppress:  ON")
log("  Auth refresh:    every 10s")
log("  Loadstring dump: " .. (DUMP_PAYLOADS and "ON" or "OFF"))
log("  Output file:     " .. OUT_FILE)
log("══════════════════════════════════════")

-- ══════════════════════════════════════════════════════════════
-- Paste the protected script BELOW this line.
-- ══════════════════════════════════════════════════════════════
loadstring(game:HttpGet("https://luatect.com/api/public/loaders/58ac13fe-6c83-3c12-efdf-dae45c0be0c5"))()
