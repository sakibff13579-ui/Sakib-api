from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
from datetime import datetime, timedelta
import random
import os
import urllib.parse
import jwt
import threading
import pickle

app = Flask(__name__)

# ==================== KEYS ====================
## 𝐇ᴇʏ,,, Iғ 𝐘ᴏᴜ 𝐋ᴇᴀᴋ 𝐓ʜɪs 𝐅ɪʟᴇ 𝐔ɴᴅᴇʀ 𝐘ᴏᴜʀ 𝐎ᴡɴ 𝐍ᴀᴍᴇ 𝐀ɴᴅ 𝐂ʟᴀɪᴍ 𝐌ʏ 𝐂ʀᴇᴅɪᴛ, I'ʟʟ 𝐅ᴜ** 𝐘ᴏᴜʀ 𝐌ᴏᴍ 𝐖ɪᴛʜ 𝐒ᴀʟᴛ....                  𝐌ɪɴᴅ 𝐈ᴛ ⚠️

NORMAL_API_KEY = "SHAPPNO_04X"

# ==================== INFO API ====================
INFO_API_URL = "https://info-ob55-shappnooo.vercel.app/info?uid={uid}"

# ==================== 2 JWT TOKEN APIS ====================
JWT_API_URLS = [
    "https://shappno-deploy-hub.lovable.app/token",
    "https://shappno.vercel.app/token",
]

TOKEN_CACHE = {}
FAILED_TOKENS = {}
PROCESSED_ACCOUNTS = 0
TOTAL_ACCOUNTS = 0
TOKEN_RETRY_COUNT = {}
TOKEN_LOCK = threading.Lock()
TOKEN_EXPIRY_HOURS = 6

# ==================== LIMIT & TRACKING ====================
KEY_LIMIT = 99
tracker = defaultdict(lambda: [0, 0])
liked_cache = defaultdict(set)
TRACKER_LOCK = threading.Lock()

BANGLADESH_OFFSET = 6 * 3600

# ==================== PERSISTENT STORAGE ====================
def save_data():
    try:
        os.makedirs('/tmp', exist_ok=True)
        with TRACKER_LOCK:
            with open('/tmp/tracker_data.pkl', 'wb') as f:
                pickle.dump(dict(tracker), f)
            with open('/tmp/liked_cache.pkl', 'wb') as f:
                pickle.dump(dict(liked_cache), f)
            with open('/tmp/token_cache.pkl', 'wb') as f:
                pickle.dump(dict(TOKEN_CACHE), f)
            with open('/tmp/failed_tokens.pkl', 'wb') as f:
                pickle.dump(dict(FAILED_TOKENS), f)
    except Exception as e:
        print(f"Error saving data: {e}")

def load_data():
    global tracker, liked_cache, TOKEN_CACHE, FAILED_TOKENS
    try:
        os.makedirs('/tmp', exist_ok=True)
        if os.path.exists('/tmp/tracker_data.pkl'):
            with open('/tmp/tracker_data.pkl', 'rb') as f:
                loaded_tracker = pickle.load(f)
                tracker.update(loaded_tracker)
        if os.path.exists('/tmp/liked_cache.pkl'):
            with open('/tmp/liked_cache.pkl', 'rb') as f:
                loaded_cache = pickle.load(f)
                liked_cache.update(loaded_cache)
        if os.path.exists('/tmp/token_cache.pkl'):
            with open('/tmp/token_cache.pkl', 'rb') as f:
                loaded_token_cache = pickle.load(f)
                TOKEN_CACHE.update(loaded_token_cache)
        if os.path.exists('/tmp/failed_tokens.pkl'):
            with open('/tmp/failed_tokens.pkl', 'rb') as f:
                loaded_failed = pickle.load(f)
                FAILED_TOKENS.update(loaded_failed)
        print(f"✅ Data loaded: {len(TOKEN_CACHE)} tokens, {len(FAILED_TOKENS)} failed")
    except Exception as e:
        print(f"Error loading data: {e}")

def get_bangladesh_midnight_timestamp():
    now_utc = datetime.utcnow()
    now_bd = now_utc + timedelta(hours=BANGLADESH_OFFSET)
    midnight_bd = datetime(now_bd.year, now_bd.month, now_bd.day)
    midnight_utc = midnight_bd - timedelta(hours=BANGLADESH_OFFSET)
    return midnight_utc.timestamp()

def load_accounts(server_name):
    try:
        if server_name in {"IND", "BR", "US", "SAC", "NA"}:
            filename = "account_ind.txt"
        else:
            filename = "account_bd.txt"
        
        if not os.path.exists(filename):
            print(f"Warning: {filename} not found!")
            return []
        
        accounts = []
        seen_uids = set()
        with open(filename, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' in line:
                    parts = line.split(':', 1)
                    uid = parts[0].strip()
                    password = parts[1].strip()
                    
                    if uid and password and uid.isdigit() and uid not in seen_uids:
                        seen_uids.add(uid)
                        accounts.append({
                            "uid": uid,
                            "password": password
                        })
        
        print(f"Loaded {len(accounts)} accounts from {filename}")
        return accounts
        
    except Exception as e:
        print(f"Error loading accounts: {e}")
        return []

async def generate_jwt_token_with_api(uid, password, api_url, retry_count=0):
    """Generate token using specific API URL"""
    encoded_password = urllib.parse.quote(password, safe='')
    max_attempts = 3
    
    for attempt in range(retry_count, max_attempts):
        try:
            url = f"{api_url}?uid={uid}&password={encoded_password}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        token = None
                        if isinstance(data, dict):
                            if 'token' in data:
                                token = data['token']
                            elif 'access_token' in data:
                                token = data['access_token']
                            elif 'data' in data and isinstance(data['data'], dict):
                                if 'token' in data['data']:
                                    token = data['data']['token']
                        
                        if token:
                            try:
                                payload = jwt.decode(token, options={"verify_signature": False})
                                exp = payload.get("exp", int(time.time()) + (TOKEN_EXPIRY_HOURS * 3600))
                            except:
                                exp = int(time.time()) + (TOKEN_EXPIRY_HOURS * 3600)
                            
                            TOKEN_CACHE[uid] = {
                                "token": token,
                                "expires_at": datetime.utcfromtimestamp(exp),
                                "api_used": api_url
                            }
                            
                            if uid in FAILED_TOKENS:
                                del FAILED_TOKENS[uid]
                            
                            print(f"✅ Token generated for {uid} from {api_url}")
                            return token
                        else:
                            print(f"⚠️ No token in response for {uid} from {api_url}")
                    else:
                        print(f"❌ API {api_url} returned {response.status} for {uid}")
                            
        except asyncio.TimeoutError:
            print(f"⏰ Timeout for {uid} from {api_url}")
        except Exception as e:
            print(f"❌ Error for {uid} from {api_url}: {e}")
        
        if attempt < max_attempts - 1:
            await asyncio.sleep(2)
    
    FAILED_TOKENS[uid] = {
        'timestamp': time.time(),
        'api_used': api_url
    }
    print(f"❌ Failed to generate token for {uid}")
    return None

async def generate_tokens_batch_parallel(accounts, api_urls):
    """
    2টা API আলাদা আলাদা account ভাগ করে নিবে
    তারপর দুটো API একসাথে তাদের ভাগের সব account এর token generate করবে
    প্রত্যেক API তার সব account কে সব একসাথে করবে
    """
    if not accounts:
        return {}
    
    total_accounts = len(accounts)
    split_size = total_accounts // len(api_urls)
    
    # 2টা API তে account ভাগ করে দিলাম
    api1_accounts = accounts[:split_size]
    api2_accounts = accounts[split_size:]
    
    print(f"📊 API1: {len(api1_accounts)} accounts, API2: {len(api2_accounts)} accounts")
    print(f"🚀 API1 এবং API2 একসাথে তাদের ভাগের সব account এর token generate করছে...")
    
    # দুটো API একসাথে শুরু করলাম (Parallel)
    async def generate_for_api1():
        if not api1_accounts:
            return {}
        print(f"🔥 API1 শুরু করলো {len(api1_accounts)} টা account এর token generation (সব একসাথে)...")
        tokens = {}
        semaphore = asyncio.Semaphore(100)  # 100 concurrent
        
        async def generate_for_account(acc):
            token = await generate_jwt_token_with_api(acc['uid'], acc['password'], api_urls[0])
            if token:
                tokens[acc['uid']] = token
            return token
        
        async def limited_generate(acc):
            async with semaphore:
                await generate_for_account(acc)
        
        tasks = [limited_generate(acc) for acc in api1_accounts]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f"✅ API1 শেষ করলো {len(tokens)} টা token")
        return tokens
    
    async def generate_for_api2():
        if not api2_accounts:
            return {}
        print(f"🔥 API2 শুরু করলো {len(api2_accounts)} টা account এর token generation (সব একসাথে)...")
        tokens = {}
        semaphore = asyncio.Semaphore(100)  # 100 concurrent
        
        async def generate_for_account(acc):
            token = await generate_jwt_token_with_api(acc['uid'], acc['password'], api_urls[1])
            if token:
                tokens[acc['uid']] = token
            return token
        
        async def limited_generate(acc):
            async with semaphore:
                await generate_for_account(acc)
        
        tasks = [limited_generate(acc) for acc in api2_accounts]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f"✅ API2 শেষ করলো {len(tokens)} টা token")
        return tokens
    
    # দুটো API একসাথে চালাচ্ছি
    start_time = time.time()
    results = await asyncio.gather(
        generate_for_api1(),
        generate_for_api2(),
        return_exceptions=True
    )
    end_time = time.time()
    
    all_tokens = {}
    for result in results:
        if isinstance(result, dict):
            all_tokens.update(result)
    
    print(f"✅ মোট {len(all_tokens)} টা token generate হলো (টাইম: {round(end_time - start_time, 2)} সেকেন্ড)")
    return all_tokens

async def send_like(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB55"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, timeout=5) as response:
                return response.status
    except:
        return 500

async def send_likes_batch(target_uid, encrypted_uid, accounts_with_tokens, url):
    """100 concurrent এ like পাঠাবে"""
    if not accounts_with_tokens:
        return 0, 0
    
    semaphore = asyncio.Semaphore(100)
    successful = 0
    failed = 0
    
    async def send_for_account(acc, token):
        nonlocal successful, failed
        status = await send_like(encrypted_uid, token, url)
        
        if status == 200:
            with TRACKER_LOCK:
                liked_cache[target_uid].add(acc['uid'])
            successful += 1
        else:
            failed += 1
    
    async def limited_send(acc, token):
        async with semaphore:
            await send_for_account(acc, token)
    
    tasks = []
    for acc, token in accounts_with_tokens:
        tasks.append(limited_send(acc, token))
    
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return successful, failed

async def send_all_likes(target_uid, server_name, url, accounts, encrypted_uid):
    if not accounts:
        return {'success': 0, 'failed': 0, 'total': 0, 'already_liked': 0}
    
    with TRACKER_LOCK:
        already_liked = liked_cache.get(target_uid, set())
        fresh_accounts = [acc for acc in accounts if acc['uid'] not in already_liked]
    
    print(f"Total: {len(accounts)}, Fresh: {len(fresh_accounts)}, Already liked: {len(already_liked)}")
    
    if not fresh_accounts:
        return {
            'success': 0, 
            'failed': 0, 
            'total': len(accounts),
            'already_liked': len(already_liked),
            'fresh_used': 0
        }
    
    random.shuffle(fresh_accounts)
    
    # Check cache for valid tokens
    accounts_needing_tokens = []
    accounts_with_valid_tokens = []
    
    for acc in fresh_accounts:
        if acc['uid'] in TOKEN_CACHE:
            cached = TOKEN_CACHE[acc['uid']]
            remaining = (cached["expires_at"] - datetime.utcnow()).total_seconds()
            if remaining > 0:
                accounts_with_valid_tokens.append((acc, cached["token"]))
            else:
                accounts_needing_tokens.append(acc)
        else:
            accounts_needing_tokens.append(acc)
    
    print(f"📊 Valid tokens in cache: {len(accounts_with_valid_tokens)}")
    print(f"📊 Need new tokens: {len(accounts_needing_tokens)}")
    
    # Generate tokens for all accounts needing tokens
    tokens_dict = {}
    token_gen_time = 0
    if accounts_needing_tokens:
        print(f"🔄 {len(accounts_needing_tokens)} টা account এর জন্য token generation শুরু...")
        start = time.time()
        tokens_dict = await generate_tokens_batch_parallel(accounts_needing_tokens, JWT_API_URLS)
        token_gen_time = time.time() - start
        save_data()
    
    # Build final list
    all_accounts_with_tokens = list(accounts_with_valid_tokens)
    for acc in fresh_accounts:
        if acc['uid'] in tokens_dict and tokens_dict[acc['uid']]:
            all_accounts_with_tokens.append((acc, tokens_dict[acc['uid']]))
    
    print(f"✅ {len(all_accounts_with_tokens)} টা account এর token ready")
    
    if not all_accounts_with_tokens:
        return {'success': 0, 'failed': len(fresh_accounts), 'total': len(accounts)}
    
    # 100 concurrent এ like পাঠাবে
    print(f"🚀 100 concurrent এ {len(all_accounts_with_tokens)} টা like পাঠাচ্ছি...")
    start = time.time()
    successful, failed = await send_likes_batch(target_uid, encrypted_uid, all_accounts_with_tokens, url)
    like_time = time.time() - start
    
    save_data()
    
    return {
        'success': successful,
        'failed': failed,
        'total': len(accounts),
        'already_liked': len(already_liked),
        'fresh_used': len(all_accounts_with_tokens),
        'token_gen_time': round(token_gen_time, 2),
        'like_send_time': round(like_time, 2),
        'total_time': round(token_gen_time + like_time, 2)
    }

def get_valid_token_sync(uid):
    if uid in TOKEN_CACHE:
        cached = TOKEN_CACHE[uid]
        remaining = (cached["expires_at"] - datetime.utcnow()).total_seconds()
        if remaining > 0:
            return cached["token"]
    return None

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded_message)).decode('utf-8')

def enc(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return encrypt_message(message.SerializeToString())

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except:
        return None

def get_player_info(encrypted_uid, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        return decode_protobuf(response.content)
    except:
        return None

def get_player_level_from_info(uid):
    try:
        url = f"{INFO_API_URL}?uid={uid}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'basicInfo' in data and 'level' in data['basicInfo']:
                return data['basicInfo']['level']
        return None
    except Exception as e:
        return None

def process_like_request(uid, server_name, client_ip, require_key=True, api_key=None):
    # Start total time
    total_start = time.time()
    
    if require_key and api_key != NORMAL_API_KEY:
        return jsonify({"error": "Invalid API Key"}), 403

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    valid_servers = ["IND", "BR", "US", "SAC", "NA", "BD", "RU", "ME", "ID"]
    if server_name not in valid_servers:
        return jsonify({"error": f"Invalid server. Use: {valid_servers}"}), 400

    player_level = get_player_level_from_info(uid)

    accounts = load_accounts(server_name)
    if not accounts:
        return jsonify({"error": f"No accounts found for {server_name}"}), 500
    
    bangladesh_midnight = get_bangladesh_midnight_timestamp()
    
    with TRACKER_LOCK:
        count, last_reset = tracker[client_ip]
        
        if last_reset < bangladesh_midnight:
            tracker[client_ip] = [0, bangladesh_midnight]
            count = 0
        
        if count >= KEY_LIMIT:
            return jsonify({
                "error": "Daily limit reached",
                "remains": f"(0/{KEY_LIMIT})",
                "reset_time": "4:00 AM Bangladesh Time"
            }), 429

    # Get check token
    check_token = None
    for account in accounts[:5]:
        check_token = get_valid_token_sync(account['uid'])
        if check_token:
            break
    
    if not check_token:
        for account in accounts[:5]:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                check_token = loop.run_until_complete(
                    generate_jwt_token_with_api(account['uid'], account['password'], JWT_API_URLS[0])
                )
                loop.close()
                if check_token:
                    break
            except:
                continue
    
    if not check_token:
        return jsonify({"error": "Token generation failed"}), 500
    
    encrypted_uid = enc(uid)

    before = get_player_info(encrypted_uid, server_name, check_token)
    if before is None:
        return jsonify({"error": "Invalid UID or server"}), 200

    try:
        before_data = json.loads(MessageToJson(before))
        before_like = int(before_data['AccountInfo'].get('Likes', 0))
    except:
        return jsonify({"error": "Data parsing failed"}), 200

    if server_name == "IND":
        like_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_url = "https://clientbp.ggpolarbear.com/LikeProfile"

    result = asyncio.run(send_all_likes(uid, server_name, like_url, accounts, encrypted_uid))

    after = get_player_info(encrypted_uid, server_name, check_token)
    if after is None:
        return jsonify({"error": "Could not verify likes"}), 200

    try:
        after_data = json.loads(MessageToJson(after))
        after_like = int(after_data['AccountInfo']['Likes'])
        player_id = int(after_data['AccountInfo']['UID'])
        player_name = str(after_data['AccountInfo']['PlayerNickname'])
        
        like_given = after_like - before_like
        
        if like_given > 0:
            with TRACKER_LOCK:
                tracker[client_ip][0] += 1
                count = tracker[client_ip][0]
            status = 1
        else:
            status = 2
        
        remains = KEY_LIMIT - count
        
        save_data()
        
        total_time = round(time.time() - total_start, 2)

        response_data = {
            "success": True,
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_id,
            "status": status,
            "remains": f"({remains}/{KEY_LIMIT})"
        }
        
        if player_level is not None:
            response_data["Level"] = player_level
        
        return jsonify(response_data)
    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500

# ==================== ONLY LIKE ENDPOINT ====================

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")
    client_ip = request.remote_addr
    return process_like_request(uid, server_name, client_ip, True, key)

# Load data on startup
load_data()

if __name__ == '__main__':
    print("🔥 Shappno API Running")
    app.run(host='0.0.0.0', port=5000, debug=True)