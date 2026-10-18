"""Atomic native-login transitions on the existing single-node Valkey owner.

Init -> issued PoW -> claimed -> session, or cancellation. A complete marker
links a late login reply to its revocable session; no provider secrets remain
in a claimed marker. These scripts never create User/Project/Cedar authority.
"""

CONFIRM_POW = """-- native-confirm-pow-v1
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, item = pcall(cjson.decode, raw)
if not ok or type(item) ~= 'table' or item.stage ~= 'init' then return 0 end
if item.issuer ~= ARGV[1] or item.client_id ~= ARGV[2] then return 0 end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if type(item.deadline_ms) ~= 'number' or item.deadline_ms <= now then return 0 end
if redis.call('GET', KEYS[2]) ~= 'reserved' then return 0 end
redis.call('SET', KEYS[2], 'issued', 'XX', 'KEEPTTL')
return 1
"""

CLAIM_INIT = """-- native-claim-init-v1
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local ok, item = pcall(cjson.decode, raw)
if ok and type(item) == 'table'
   and (item.stage == 'claimed' or item.stage == 'complete') then return false end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = redis.call('PTTL', KEYS[1])
if not ok or type(item) ~= 'table' or item.stage ~= 'init'
   or item.issuer ~= ARGV[1] or item.client_id ~= ARGV[2]
   or type(item.deadline_ms) ~= 'number' or item.deadline_ms <= now or ttl < 1
   or redis.call('GET', KEYS[2]) ~= 'issued' then
    redis.call('DEL', KEYS[1], KEYS[2])
    return false
end
local marker = cjson.encode({stage='claimed', claim=ARGV[3],
    deadline_ms=item.deadline_ms, issuer=item.issuer, client_id=item.client_id})
redis.call('SET', KEYS[1], marker, 'PX', ttl)
redis.call('DEL', KEYS[2])
return raw
"""

COMPLETE_LOGIN = """-- native-complete-login-v1
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, item = pcall(cjson.decode, raw)
if not ok or type(item) ~= 'table' or item.stage ~= 'claimed'
   or item.claim ~= ARGV[1] then return 0 end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if type(item.deadline_ms) ~= 'number' or item.deadline_ms <= now then return 0 end
local session_deadline = tonumber(ARGV[3])
local ttl = math.floor(session_deadline - now)
if ttl < 1000 or ttl > 900000 then return 0 end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return -1 end
-- Lua runtime errors do not roll back writes. Put cancellation linkage FIRST;
-- no target session exists yet. If allocation then fails, no cookie is issued.
local marker = cjson.encode({stage='complete', session_key=KEYS[2]})
redis.call('SET', KEYS[1], marker, 'PX', ttl)
local saved = redis.pcall('SET', KEYS[2], ARGV[2], 'PX', ttl, 'NX')
if type(saved) == 'table' and saved.err then
    redis.call('DEL', KEYS[1])
    return redis.error_reply('native session allocation unavailable')
end
if not saved then
    redis.call('DEL', KEYS[1])
    return -1
end
return 1
"""

CANCEL_LOGIN = """-- native-cancel-login-v1
local raw = redis.call('GET', KEYS[1])
if raw then
    local ok, item = pcall(cjson.decode, raw)
    if not ok or type(item) ~= 'table' then return -1 end
    if item.stage == 'complete' then
        local target = item.session_key
        local prefix = ARGV[1]
        if type(target) ~= 'string' or string.sub(target, 1, #prefix) ~= prefix
           or #target ~= #prefix + 64
           or not string.match(string.sub(target, #prefix + 1), '^[a-f0-9]+$') then
            return -1
        end
        redis.call('DEL', target)
    end
end
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"""

STAGE_OTP = """-- native-stage-otp-v1
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, item = pcall(cjson.decode, raw)
if not ok or type(item) ~= 'table' or item.stage ~= 'claimed'
   or item.claim ~= ARGV[1] then return 0 end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = redis.call('PTTL', KEYS[1])
if type(item.deadline_ms) ~= 'number' or item.deadline_ms <= now or ttl < 1 then return 0 end
local good, update = pcall(cjson.decode, ARGV[2])
if not good or type(update) ~= 'table' or update.stage ~= 'otp_ready'
   or update.claim ~= item.claim or update.deadline_ms ~= item.deadline_ms
   or update.issuer ~= item.issuer or update.client_id ~= item.client_id then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'PX', ttl)
return 1
"""

CLAIM_OTP_START = """-- native-claim-otp-start-v1
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local ok, item = pcall(cjson.decode, raw)
if not ok or type(item) ~= 'table' or item.stage ~= 'otp_ready'
   or item.issuer ~= ARGV[1] or item.client_id ~= ARGV[2]
   or type(item.methods) ~= 'table' then return false end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = redis.call('PTTL', KEYS[1])
if type(item.deadline_ms) ~= 'number' or item.deadline_ms <= now or ttl < 1 then return false end
local index = tonumber(ARGV[3])
if not index or index < 0 or index % 1 ~= 0
   or index >= #item.methods or not item.methods[index + 1] then return false end
item.selected_otp_id = item.methods[index + 1].id
item.otp_claim = ARGV[4]
item.stage = 'otp_starting'
redis.call('SET', KEYS[1], cjson.encode(item), 'PX', ttl)
return raw
"""

CONFIRM_OTP_START = """-- native-confirm-otp-start-v1
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, item = pcall(cjson.decode, raw)
if not ok or type(item) ~= 'table' or item.stage ~= 'otp_starting'
   or item.otp_claim ~= ARGV[1] then return 0 end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = redis.call('PTTL', KEYS[1])
local otp_expires = tonumber(ARGV[3])
if type(item.deadline_ms) ~= 'number' or item.deadline_ms <= now or ttl < 1
   or not otp_expires or otp_expires <= now then return 0 end
item.stage = 'otp_started'
item.otp_code = ARGV[2]
item.otp_expires_ms = otp_expires
item.provider_cookie = ARGV[4]
item.csrf = ARGV[5]
item.otp_login_code = nil
item.methods = nil
item.selected_otp_id = nil
redis.call('SET', KEYS[1], cjson.encode(item), 'PX', ttl)
return 1
"""

CLAIM_OTP_FINISH = """-- native-claim-otp-finish-v1
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local ok, item = pcall(cjson.decode, raw)
if not ok or type(item) ~= 'table' or item.stage ~= 'otp_started'
   or item.issuer ~= ARGV[1] or item.client_id ~= ARGV[2]
   or type(item.claim) ~= 'string' then return false end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = redis.call('PTTL', KEYS[1])
if type(item.deadline_ms) ~= 'number' or item.deadline_ms <= now or ttl < 1
   or type(item.otp_expires_ms) ~= 'number' or item.otp_expires_ms <= now then return false end
-- Secret-free original claim restored only for ONE verified PKCE redemption.
local marker = cjson.encode({stage='claimed', claim=item.claim,
    deadline_ms=item.deadline_ms, issuer=item.issuer, client_id=item.client_id})
redis.call('SET', KEYS[1], marker, 'PX', ttl)
return raw
"""
