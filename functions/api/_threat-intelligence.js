import { getRedis } from "./_redis.js";

const THREAT_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const THREAT_DECAY_MS = 30 * 60 * 1000;

const MAX_IP_LENGTH = 100;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_USER_ID_LENGTH = 128;
const MAX_ROUTE_LENGTH = 150;
const MAX_REASON_LENGTH = 100;
const MAX_REASON_HISTORY = 50;

const ALLOWED_ROUTE_SENSITIVITY = new Set(["normal","high","critical"]);

/* ---------- helpers ---------- */

function safeString(value,maxLength=300){
  return String(value||"")
    .replace(/[\u0000-\u001F\u007F]/g,"")
    .trim()
    .slice(0,maxLength);
}

function safeNumber(value,fallback=0){
  const num=Number(value);
  return Number.isFinite(num)?num:fallback;
}

function safeInt(value,fallback=0,min=0,max=1_000_000){
  const num=Math.floor(safeNumber(value,fallback));
  if(!Number.isFinite(num)) return fallback;
  return Math.min(max,Math.max(min,num));
}

function safeTimestamp(value,fallback=0){
  return safeInt(value,fallback,0,Date.now()+60000);
}

function safeJsonParse(raw,fallback=null){
  try{
    return JSON.parse(raw);
  }catch{
    return fallback;
  }
}

/* ---------- normalization ---------- */

function sanitizeKeyPart(value="",maxLength=120,fallback=""){
  const cleaned=safeString(value,maxLength)
    .replace(/[^a-zA-Z0-9._:@/-]/g,"");
  return cleaned||fallback;
}

function normalizeIp(value=""){
  let ip=safeString(value||"unknown",MAX_IP_LENGTH);

  if(ip.startsWith("::ffff:")){
    ip=ip.slice(7);
  }

  ip=ip.replace(/[^a-fA-F0-9:.,]/g,"").slice(0,MAX_IP_LENGTH);

  return ip||"unknown";
}

function normalizeSessionId(value=""){
  return sanitizeKeyPart(value||"no-session",MAX_SESSION_ID_LENGTH,"no-session");
}

function normalizeUserId(value=""){
  return sanitizeKeyPart(value||"anon-user",MAX_USER_ID_LENGTH,"anon-user");
}

function normalizeRoute(value=""){
  const raw=safeString(value||"unknown-route",MAX_ROUTE_LENGTH*2);

  const cleaned=raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g,"/")
    .replace(/[^a-zA-Z0-9/_:-]/g,"")
    .toLowerCase()
    .slice(0,MAX_ROUTE_LENGTH);

  return cleaned||"unknown-route";
}

function normalizeRouteSensitivity(value="normal"){
  const normalized=safeString(value,20).toLowerCase();
  return ALLOWED_ROUTE_SENSITIVITY.has(normalized)
    ? normalized
    : "normal";
}

/* ---------- Redis helpers ---------- */

function buildThreatKey({ip="",sessionId="",userId=""}={}){
  return `threat:${normalizeIp(ip)}::${normalizeSessionId(sessionId)}::${normalizeUserId(userId)}`;
}

async function getStoredThreatRecord(env,redisKey,now){
  const redis=getRedis(env);

  try{
    const raw=await redis.get(redisKey);

    if(!raw) return null;

    if(typeof raw==="string"){
      const parsed=safeJsonParse(raw,null);
      return parsed;
    }

    if(typeof raw==="object"){
      return raw;
    }

    return null;

  }catch(err){
    console.error("Threat intelligence read failed:",err);
    return null;
  }
}

async function storeThreatRecord(env,redisKey,record){
  const redis=getRedis(env);

  try{
    const ttlSeconds=Math.max(1,Math.ceil(THREAT_STATE_TTL_MS/1000));

    await redis.set(
      redisKey,
      JSON.stringify(record),
      {ex:ttlSeconds}
    );

    return true;

  }catch(err){
    console.error("Threat intelligence write failed:",err);
    return false;
  }
}

/* ---------- public API ---------- */

export async function evaluateThreat({
  env={},
  ip="",
  sessionId="",
  userId="",
  route=""
}={}){

  const now=Date.now();
  const redisKey=buildThreatKey({ip,sessionId,userId});

  let record=await getStoredThreatRecord(env,redisKey,now);

  if(!record){
    record={
      createdAt:now,
      updatedAt:now,
      threatScore:0,
      highestThreatScore:0,
      lastRoute:"unknown-route",
      reasonHistory:[]
    };
  }

  record.updatedAt=now;
  record.lastRoute=normalizeRoute(route);

  await storeThreatRecord(env,redisKey,record);

  return {
    threatScore:safeInt(record.threatScore,0,0,100),
    level:"low",
    action:"allow",
    clientKeyPreview:safeString(redisKey.replace(/^threat:/,""),24)
  };
}

export async function getThreatSnapshot({
  env={},
  ip="",
  sessionId="",
  userId=""
}={}){

  const redisKey=buildThreatKey({ip,sessionId,userId});
  const record=await getStoredThreatRecord(env,redisKey,Date.now());

  if(!record){
    return {
      found:false,
      clientKeyPreview:safeString(redisKey.replace(/^threat:/,""),24)
    };
  }

  return {
    found:true,
    threatScore:safeInt(record.threatScore,0,0,100),
    highestThreatScore:safeInt(record.highestThreatScore,0,0,100),
    lastRoute:normalizeRoute(record.lastRoute),
    clientKeyPreview:safeString(redisKey.replace(/^threat:/,""),24)
  };
}

export async function clearThreatSnapshot({
  env={},
  ip="",
  sessionId="",
  userId=""
}={}){

  const redis=getRedis(env);
  const redisKey=buildThreatKey({ip,sessionId,userId});

  try{
    await redis.del(redisKey);
    return {ok:true};
  }catch(err){
    console.error("Threat intelligence delete failed:",err);
    return {ok:false};
  }
}
