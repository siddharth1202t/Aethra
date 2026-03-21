import { getRedis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const ANOMALY_STATE_PREFIX = "security:anomaly-state";

const ANOMALY_STATE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const ANOMALY_STATE_TTL_SECONDS = Math.max(
  1,
  Math.ceil(ANOMALY_STATE_TTL_MS / 1000)
);

const MAX_COUNTER_VALUE = 1_000_000;
const MAX_REASON_LENGTH = 120;
const MAX_REASONS = 20;
const MAX_RECENT_ITEMS = 10;

const ALLOWED_LEVELS = new Set(["low","medium","high","critical"]);
const ALLOWED_ACTIONS = new Set(["allow","throttle","challenge","block"]);

/* ------------------------------------------------ */
/* SAFETY HELPERS */
/* ------------------------------------------------ */

function safeString(value, maxLength = 200) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeInt(value, fallback = 0, min = 0, max = MAX_COUNTER_VALUE) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

/* ------------------------------------------------ */
/* NORMALIZATION */
/* ------------------------------------------------ */

function normalizeLevel(value="low"){
  const v = safeString(value,20).toLowerCase();
  return ALLOWED_LEVELS.has(v) ? v : "low";
}

function normalizeAction(value="allow"){
  const v = safeString(value,20).toLowerCase();
  return ALLOWED_ACTIONS.has(v) ? v : "allow";
}

function normalizeKey(value=""){
  return safeString(value,160).replace(/[^a-zA-Z0-9:_-]/g,"_");
}

function normalizeRoute(value=""){
  const raw = safeString(value,300);
  if(!raw) return "";

  return raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g,"/")
    .replace(/[^a-zA-Z0-9/_-]/g,"")
    .toLowerCase()
    .slice(0,200);
}

function normalizeIp(value=""){
  return safeString(value,100);
}

function normalizeReason(reason=""){
  return safeString(reason,MAX_REASON_LENGTH)
    .replace(/[^\w:.-]/g,"_");
}

/* ------------------------------------------------ */
/* STATE */
/* ------------------------------------------------ */

function buildStateKey(actorType,actorId){
  return `${ANOMALY_STATE_PREFIX}:${normalizeKey(actorType)}:${normalizeKey(actorId)}`;
}

function createDefaultState(actorType="session",actorId=""){
  const now = Date.now();

  return {
    actorType:normalizeKey(actorType),
    actorId:normalizeKey(actorId),

    updatedAt:now,
    createdAt:now,

    recentIps:[],
    recentRoutes:[],
    recentActions:[],
    recentRiskScores:[],

    loginCount:0,
    signupCount:0,
    passwordResetCount:0,
    writeActionCount:0,

    suspiciousBurstCount:0,
    ipChangeCount:0,
    routeSpreadCount:0
  };
}

function normalizeStringArray(values=[],maxItems=MAX_RECENT_ITEMS){
  if(!Array.isArray(values)) return [];

  const out=[];
  for(const v of values){
    const s=safeString(v,200);
    if(!s) continue;

    if(!out.includes(s)){
      out.push(s);
    }

    if(out.length>=maxItems) break;
  }

  return out;
}

function normalizeNumberArray(values=[],maxItems=MAX_RECENT_ITEMS){
  if(!Array.isArray(values)) return [];

  const out=[];
  for(const v of values){
    out.push(safeInt(v,0,0,100));
    if(out.length>=maxItems) break;
  }

  return out;
}

function normalizeState(raw,actorType="session",actorId=""){
  const base=createDefaultState(actorType,actorId);
  const s=raw && typeof raw==="object" ? raw : {};

  return {
    actorType:normalizeKey(s.actorType||base.actorType),
    actorId:normalizeKey(s.actorId||base.actorId),

    updatedAt:safeInt(s.updatedAt,base.updatedAt,0,Date.now()+60000),
    createdAt:safeInt(s.createdAt,base.createdAt,0,Date.now()+60000),

    recentIps:normalizeStringArray(s.recentIps),
    recentRoutes:normalizeStringArray(s.recentRoutes),
    recentActions:normalizeStringArray(s.recentActions),
    recentRiskScores:normalizeNumberArray(s.recentRiskScores),

    loginCount:safeInt(s.loginCount),
    signupCount:safeInt(s.signupCount),
    passwordResetCount:safeInt(s.passwordResetCount),
    writeActionCount:safeInt(s.writeActionCount),

    suspiciousBurstCount:safeInt(s.suspiciousBurstCount),
    ipChangeCount:safeInt(s.ipChangeCount),
    routeSpreadCount:safeInt(s.routeSpreadCount)
  };
}

/* ------------------------------------------------ */
/* REDIS STORAGE */
/* ------------------------------------------------ */

async function getStoredState(env,actorType,actorId){

  const redis=getRedis(env);

  const safeActorType=normalizeKey(actorType);
  const safeActorId=normalizeKey(actorId);

  if(!safeActorId){
    return createDefaultState(safeActorType,safeActorId);
  }

  try{

    const key=buildStateKey(safeActorType,safeActorId);

    const raw=await redis.get(key);

    if(!raw){
      return createDefaultState(safeActorType,safeActorId);
    }

    if(typeof raw==="string"){
      const parsed=safeJsonParse(raw,null);
      return normalizeState(parsed,safeActorType,safeActorId);
    }

    if(typeof raw==="object"){
      return normalizeState(raw,safeActorType,safeActorId);
    }

    return createDefaultState(safeActorType,safeActorId);

  }catch(err){

    console.error("Anomaly state read failed:",err);
    return createDefaultState(safeActorType,safeActorId);

  }
}

async function storeState(env,state){

  const redis=getRedis(env);

  const normalized=normalizeState(
    state,
    state?.actorType || "session",
    state?.actorId || ""
  );

  if(!normalized.actorId){
    return false;
  }

  try{

    const key=buildStateKey(normalized.actorType,normalized.actorId);

    await redis.set(
      key,
      JSON.stringify(normalized),
      {ex:ANOMALY_STATE_TTL_SECONDS}
    );

    return true;

  }catch(err){

    console.error("Anomaly state write failed:",err);
    return false;

  }
}

/* ------------------------------------------------ */
/* ANOMALY SCORE */
/* ------------------------------------------------ */

function getLevel(score){
  const s=safeInt(score,0,0,100);

  if(s>=90) return "critical";
  if(s>=70) return "high";
  if(s>=40) return "medium";
  return "low";
}

function getAction(score){
  const s=safeInt(score,0,0,100);

  if(s>=90) return "block";
  if(s>=70) return "challenge";
  if(s>=40) return "throttle";
  return "allow";
}

function pushReason(list,reason){
  const r=normalizeReason(reason);
  if(!r) return;

  if(!list.includes(r)){
    list.push(r);
  }
}

/* ------------------------------------------------ */
/* MAIN ENGINE */
/* ------------------------------------------------ */

export async function evaluateAnomalyDetection({

  env={},

  actorType="session",
  actorId="",

  ip="",
  route="",

  riskScore=0,

  isWriteAction=false,
  actionType=""

}={}){

  const safeActorType=normalizeKey(actorType);
  const safeActorId=normalizeKey(actorId);

  if(!safeActorId){
    return {
      anomalyScore:0,
      level:"low",
      action:"allow",
      reasons:[]
    };
  }

  const currentIp=normalizeIp(ip);
  const currentRoute=normalizeRoute(route);

  const previousState=
    await getStoredState(env,safeActorType,safeActorId);

  const now=Date.now();

  const nextState=normalizeState({

    ...previousState,

    updatedAt:now,

    recentIps:
      currentIp
        ? [currentIp,...previousState.recentIps.filter(v=>v!==currentIp)].slice(0,MAX_RECENT_ITEMS)
        : previousState.recentIps,

    recentRoutes:
      currentRoute
        ? [currentRoute,...previousState.recentRoutes.filter(v=>v!==currentRoute)].slice(0,MAX_RECENT_ITEMS)
        : previousState.recentRoutes,

    recentRiskScores:
      [safeInt(riskScore,0,0,100),...previousState.recentRiskScores]
        .slice(0,MAX_RECENT_ITEMS)

  },safeActorType,safeActorId);

  /* basic anomaly scoring */

  let score=0;
  const reasons=[];

  const safeRisk=safeInt(riskScore,0,0,100);

  if(safeRisk>=80){
    score+=25;
    pushReason(reasons,"anomaly:high_risk_alignment");
  }

  if(
    currentIp &&
    previousState.recentIps.length>0 &&
    !previousState.recentIps.includes(currentIp)
  ){
    score+=20;
    pushReason(reasons,"anomaly:ip_change_detected");
  }

  if(
    currentRoute &&
    !previousState.recentRoutes.includes(currentRoute) &&
    previousState.recentRoutes.length>=4
  ){
    score+=10;
    pushReason(reasons,"anomaly:new_route_after_wide_spread");
  }

  if(isWriteAction){
    score+=8;
    pushReason(reasons,"anomaly:write_action_pressure");
  }

  const anomalyScore=Math.min(100,Math.max(0,score));

  const result={
    anomalyScore,
    level:getLevel(anomalyScore),
    action:getAction(anomalyScore),
    reasons:reasons.slice(0,MAX_REASONS)
  };

  const ok=await storeState(env,nextState);

  if(ok && anomalyScore>=40){

    try{

      await appendSecurityEvent({

        type:"anomaly_detected",

        severity:
          result.level==="critical"
            ?"critical"
            :result.level==="high"
            ?"warning"
            :"info",

        action:
          result.action==="block" ||
          result.action==="challenge" ||
          result.action==="throttle"
            ? result.action
            : "observe",

        route:currentRoute,
        ip:currentIp,

        reason:result.reasons[0] || "anomaly_detected",

        message:"Behavioral anomaly detected for actor.",

        metadata:{
          actorType:safeActorType,
          actorId:safeActorId,
          anomalyScore:result.anomalyScore
        }

      });

    }catch(err){

      console.error("Anomaly event write failed:",err);

    }

  }

  return result;

}
