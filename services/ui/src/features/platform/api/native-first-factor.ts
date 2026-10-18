import {CONTROL_PANEL_AUTH_API} from "@/shared/config/control-panel-api"
import {readBoundedJsonResponse,readBoundedErrorCode} from "@/shared/lib/bounded-json-response"
import {checkNativePrelogin} from "./native-prelogin-control"
import {prepareNativeRauthyLogin} from "./native-rauthy"
import {solveRauthyPow,validRauthyPowChallenge} from "../model/rauthy-pow"

/** Rauthy owns identity. A successful first factor only creates an opaque
 * cookie-bound browser session. It is NOT a Platform User/Project/Cedar grant.
 */
export type NativeLoginOutcome =
  | {kind:"session_issued"}
  | {kind:"continuation_unavailable";stage:"otp_pending"|"webauthn_pending"|"tos_pending"|"account_update_required"|"client_mfa_required"}
  | {kind:"rejected"|"provider_rejected"|"unavailable"|"expired"|"rate_limited"|"cancelled"|"uncertain";code:string}

const unsupportedStages=["otp_pending","webauthn_pending","tos_pending","account_update_required","client_mfa_required"] as const
const requestHeaders={Accept:"application/json","Content-Type":"application/json"}
const postSettings={
  method:"POST",credentials:"same-origin",mode:"same-origin",cache:"no-store",
  referrerPolicy:"no-referrer",redirect:"error",headers:requestHeaders,
} as const
function object(value:unknown):Record<string,unknown>|null{
  return typeof value==="object"&&value!==null&&!Array.isArray(value)
    ?value as Record<string,unknown>:null
}
function exact(value:Record<string,unknown>,fields:readonly string[]):boolean{
  return Object.keys(value).length===fields.length&&
    fields.every(field=>Object.prototype.hasOwnProperty.call(value,field))
}
function validCredentials(email:string,password:string):boolean{
  return email.length>=3&&email.length<=320&&email.split("@").length===2&&
    !/[\x00-\x20\x7f]/.test(email)&&email===email.trim()&&
    password.length>=1&&password.length<=256
}
function secureBrowser():boolean{
  return typeof window!=="undefined"&&window.location.protocol==="https:"&&
    window.isSecureContext===true
}
/** Provider's public challenge expires independently of the Init cookie.
 * A rollback in the device wall clock cannot extend a PoW already observed.
 * Keep a small delivery margin so a worker finishing at the boundary never
 * triggers a doomed password submission.
 */
export function usableNativePowDeadline(
  challenge:string,
  observedWallMs:number,
  observedMonotonicMs:number,
  nowWallMs:number,
  nowMonotonicMs:number,
):boolean{
  const match=/^1:\d{2}:(\d{10}):/.exec(challenge)
  if(!match||![observedWallMs,observedMonotonicMs,nowWallMs,nowMonotonicMs]
    .every(Number.isFinite))return false
  const elapsed=nowMonotonicMs-observedMonotonicMs
  if(elapsed<0)return false
  const expires=Number(match[1])*1000
  return expires-Math.max(nowWallMs,observedWallMs+elapsed)>1500
}
function error(kind:NativeLoginOutcome["kind"],code:string):NativeLoginOutcome{
  if(kind==="rejected"||kind==="provider_rejected"||kind==="unavailable"||kind==="expired"||
    kind==="rate_limited"||kind==="cancelled"||kind==="uncertain")return {kind,code}
  return {kind:"unavailable",code}
}
/** Execute exactly one explicit password attempt. NO automatic replay of
 * consumed PoW/credentials. Cancel/timeout after a dispatched first factor
 * returns uncertain; the UI must perform a separate signed session read.
 *
 * This function never stores or logs email, password, challenge, session
 * cookies, provider tokens or credential responses.
 */
export async function submitNativePasswordLogin(
  email:string,password:string,signal:AbortSignal,
):Promise<NativeLoginOutcome>{
  if(signal.aborted)return {kind:"cancelled",code:"NATIVE_LOGIN_CANCELLED"}
  if(!secureBrowser())return {kind:"unavailable",code:"NATIVE_SECURE_CONTEXT_REQUIRED"}
  if(!validCredentials(email,password))return {kind:"rejected",code:"NATIVE_CREDENTIALS_INVALID"}
  const protocol=await checkNativePrelogin(signal)
  if(signal.aborted)return {kind:"cancelled",code:"NATIVE_LOGIN_CANCELLED"}
  if(protocol.kind!=="supported")return error("unavailable",protocol.code)
  const init=await prepareNativeRauthyLogin(signal)
  if(signal.aborted)return {kind:"cancelled",code:"NATIVE_LOGIN_CANCELLED"}
  if(init.kind!=="prepared")return error(init.kind==="expired"?"expired":"unavailable",init.code)
  let credentialDispatched=false
  try{
    const challengeResponse=await fetch(CONTROL_PANEL_AUTH_API+"/pow",{
      ...postSettings,signal,body:"{}",
    })
    if(signal.aborted)return {kind:"cancelled",code:"NATIVE_LOGIN_CANCELLED"}
    if(challengeResponse.status!==200){
      const code=await readBoundedErrorCode(challengeResponse,signal,"NATIVE_POW_UNAVAILABLE")
      return error(challengeResponse.status===401?"expired":"unavailable",code)
    }
    const data=object(await readBoundedJsonResponse(challengeResponse,signal,4096))
    const challenge=data?.challenge
    if(!data||!exact(data,["challenge","authenticated"])||
      data.authenticated!==false||!validRauthyPowChallenge(challenge)){
      return {kind:"unavailable",code:"NATIVE_POW_INVALID"}
    }
    const powObservedWall=Date.now(),powObservedMonotonic=performance.now()
    const solution=await solveRauthyPow(challenge,signal)
    if(signal.aborted||solution.kind==="cancelled")return {kind:"cancelled",code:"NATIVE_LOGIN_CANCELLED"}
    if(solution.kind!=="solved")return {kind:"unavailable",code:"NATIVE_POW_UNAVAILABLE"}
    if(!usableNativePowDeadline(challenge,powObservedWall,powObservedMonotonic,Date.now(),performance.now())||
      Date.now()>=init.expiresAt)return {kind:"expired",code:"NATIVE_LOGIN_EXPIRED"}
    const body=JSON.stringify({email,password,pow:solution.work})
    if(new TextEncoder().encode(body).length>8192)return {kind:"rejected",code:"NATIVE_REQUEST_INVALID"}
    if(signal.aborted)return {kind:"cancelled",code:"NATIVE_LOGIN_CANCELLED"}
    credentialDispatched=true
    const reply=await fetch(CONTROL_PANEL_AUTH_API+"/first-factor",{
      ...postSettings,signal,body,
    })
    if(signal.aborted)return {kind:"uncertain",code:"NATIVE_LOGIN_RESULT_UNCERTAIN"}
    if(reply.status===200){
      const completed=object(await readBoundedJsonResponse(reply,signal,4096))
      if(signal.aborted)return {kind:"uncertain",code:"NATIVE_LOGIN_RESULT_UNCERTAIN"}
      if(completed&&exact(completed,["stage","authenticated","authority","platform_membership_verified","permissions"])&&
        completed.stage==="authenticated"&&completed.authenticated===true&&
        completed.authority==="rauthy"&&completed.platform_membership_verified===false&&
        Array.isArray(completed.permissions)&&completed.permissions.length===0){
        return {kind:"session_issued"}
      }
      return {kind:"uncertain",code:"NATIVE_LOGIN_RESPONSE_INVALID"}
    }
    if(reply.status===202){
      // Backend may now offer a private email OTP continuation. This v1
      // Frontend has no supported OTP form yet, so do NOT silently treat 202
      // as session issuance or fall back to an authenticated Panel.
      const step=object(await readBoundedJsonResponse(reply,signal,4096))
      if(signal.aborted)return {kind:"uncertain",code:"NATIVE_LOGIN_RESULT_UNCERTAIN"}
      const methods=step?.methods
      if(step&&exact(step,["stage","authenticated","continuation_available","methods"])&&
        step.stage==="otp_pending"&&step.authenticated===false&&
        step.continuation_available===true&&Array.isArray(methods)&&
        methods.length>=1&&methods.length<=10&&
        methods.every((item,index)=>{
          const m=object(item)
          return !!m&&exact(m,["index","kind"])&&m.index===index&&m.kind==="email"
        })){
        return {kind:"continuation_unavailable",stage:"otp_pending"}
      }
      return {kind:"unavailable",code:"NATIVE_CONTINUATION_INVALID"}
    }
    if(reply.status===409){
      const continuation=object(await readBoundedJsonResponse(reply,signal,4096))
      if(continuation&&exact(continuation,["stage","authenticated","continuation_available","restart_required"])&&
        continuation.authenticated===false&&continuation.continuation_available===false&&
        continuation.restart_required===true&&
        unsupportedStages.some(stage=>stage===continuation.stage)){
        return {kind:"continuation_unavailable",stage:continuation.stage as typeof unsupportedStages[number]}
      }
      return {kind:"unavailable",code:"NATIVE_CONTINUATION_INVALID"}
    }
    const code=await readBoundedErrorCode(reply,signal,"NATIVE_LOGIN_UNAVAILABLE")
    if(signal.aborted)return {kind:"uncertain",code:"NATIVE_LOGIN_RESULT_UNCERTAIN"}
    if(reply.status===401&&code==="NATIVE_PROVIDER_AUTH_REJECTED")return {kind:"provider_rejected",code}
    if(reply.status===401||reply.status===422)return {kind:"rejected",code}
    if(reply.status===429)return {kind:"rate_limited",code}
    return {kind:"unavailable",code}
  }catch{
    return {kind:credentialDispatched?"uncertain":"unavailable",code:credentialDispatched?"NATIVE_LOGIN_RESULT_UNCERTAIN":"NATIVE_LOGIN_UNAVAILABLE"}
  }
}
