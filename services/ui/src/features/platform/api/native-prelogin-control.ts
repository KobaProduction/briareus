import {CONTROL_PANEL_AUTH_API} from "@/shared/config/control-panel-api"
/** Native prelogin controls from the Backend-owned rauthy-native-v1 protocol.
 * These endpoints never collect credentials or establish Rauthy/Platform identity.
 * They are safe to call only in the existing same-origin HTTPS browser.
 */
export type NativePreloginCapabilities =
  | {kind:"supported"}
  | {kind:"unavailable"|"invalid"|"forbidden";code:string}
export type NativeCancellation =
  | {kind:"cancelled"}
  | {kind:"unavailable"|"forbidden";code:string}

function object(value:unknown):Record<string,unknown>|null{
  return value!==null&&typeof value==="object"&&!Array.isArray(value)
    ?value as Record<string,unknown>:null
}
function shape(value:Record<string,unknown>,expected:readonly string[]):boolean{
  return Object.keys(value).length===expected.length&&
    Object.keys(value).every(key=>expected.includes(key))
}
/** Exact protocol replies are tiny. Never run unbounded response.json()
 * against a public prelogin endpoint or let a stalled response body keep
 * the entry screen busy after its AbortSignal expires.
 */
async function boundedNativeJson(reply:Response,signal:AbortSignal):Promise<unknown>{
  const media=reply.headers.get("content-type")?.split(";",1)[0].trim()
  if(media!=="application/json")throw Error("unexpected native JSON media")
  const ceiling=4096,size=reply.headers.get("content-length")
  if(size!==null&&(!/^\d{1,6}$/.test(size)||Number(size)>ceiling))throw Error("native reply too large")
  if(signal.aborted||!reply.body)throw Error("native reply cancelled or missing")
  const reader=reply.body.getReader()
  const chunks:Uint8Array[]=[],partsMax=ceiling
  let total=0,abortRead:((reason:Error)=>void)|null=null
  const interruption=new Promise<never>((_resolve,reject)=>{abortRead=reject})
  const onAbort=():void=>{
    abortRead?.(new Error("native reply cancelled"))
    try{void reader.cancel().catch(()=>{})}catch{/* already closed */}
  }
  signal.addEventListener("abort",onAbort,{once:true})
  try{
    if(signal.aborted)throw Error("native reply cancelled")
    while(true){
      const next=await Promise.race([reader.read(),interruption])
      if(next.done)break
      total+=next.value.byteLength
      if(total>partsMax)throw Error("native reply too large")
      chunks.push(next.value)
      if(signal.aborted)throw Error("native reply cancelled")
    }
  }catch(error){
    try{void reader.cancel().catch(()=>{})}catch{/* already closed */}
    throw error
  }finally{
    signal.removeEventListener("abort",onAbort)
    reader.releaseLock()
  }
  if(signal.aborted)throw Error("native reply cancelled")
  const bytes=new Uint8Array(total)
  let offset=0
  for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength}
  return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)) as unknown
}
async function serverError(response:Response,signal:AbortSignal):Promise<string>{
  try{
    const payload=object(await boundedNativeJson(response,signal)),detail=object(payload?.error)
    const code=detail?.code
    return typeof code==="string"&&/^[A-Z][A-Z_]{0,63}$/.test(code)?code:"NATIVE_UNAVAILABLE"
  }catch{return "NATIVE_UNAVAILABLE"}
}

/** Accept only the two exact advertised Backend v1 profiles:
 * password-only [] and password+OTP ["otp"]. An OTP capability describes
 * a possible server continuation, NEVER proof the specific user needs OTP,
 * has supplied a valid password or owns a Platform role. All other names,
 * duplicate entries and missing fields remain rejected before Init.
 */
export async function checkNativePrelogin(signal:AbortSignal):Promise<NativePreloginCapabilities>{
  if(signal.aborted)return {kind:"unavailable",code:"NATIVE_CAPABILITIES_CANCELLED"}
  try{
    const response=await fetch(CONTROL_PANEL_AUTH_API+"/capabilities",{
      method:"GET",credentials:"same-origin",mode:"same-origin",cache:"no-store",
      redirect:"error",referrerPolicy:"no-referrer",signal,
      headers:{Accept:"application/json"},
    })
    if(signal.aborted)return {kind:"unavailable",code:"NATIVE_CAPABILITIES_CANCELLED"}
    if(response.status!==200){
      const code=await serverError(response,signal)
      if(signal.aborted)return {kind:"unavailable",code:"NATIVE_CAPABILITIES_CANCELLED"}
      return {kind:response.status===403?"forbidden":"unavailable",code}
    }
    const body=object(await boundedNativeJson(response,signal))
    if(!body||!shape(body,["protocol","first_factor","pow","cancel","continuations"])||
      body.protocol!=="rauthy-native-v1"||body.first_factor!=="password"||
      body.pow!=="client-solved"||body.cancel!==true||
      !Array.isArray(body.continuations)||
      !(body.continuations.length===0||
        (body.continuations.length===1&&body.continuations[0]==="otp"))){
      return {kind:"invalid",code:"NATIVE_CAPABILITIES_INVALID"}
    }
    if(signal.aborted)return {kind:"unavailable",code:"NATIVE_CAPABILITIES_CANCELLED"}
    return {kind:"supported"}
  }catch{return {kind:"unavailable",code:"NATIVE_CAPABILITIES_UNAVAILABLE"}}
}

/** Only explicit user cancellation; never revoke a completed signed-in session.
 * A timeout is uncertain: the UI must not report that cleanup succeeded. */
export async function cancelNativePrelogin(signal:AbortSignal):Promise<NativeCancellation>{
  if(signal.aborted)return {kind:"unavailable",code:"NATIVE_CANCEL_CANCELLED"}
  try{
    const response=await fetch(CONTROL_PANEL_AUTH_API+"/cancel",{
      method:"POST",credentials:"same-origin",mode:"same-origin",cache:"no-store",
      redirect:"error",referrerPolicy:"no-referrer",signal,
      headers:{Accept:"application/json","Content-Type":"application/json"},body:"{}",
    })
    if(signal.aborted)return {kind:"unavailable",code:"NATIVE_CANCEL_UNCERTAIN"}
    if(response.status===204)return {kind:"cancelled"}
    const code=await serverError(response,signal)
    if(signal.aborted)return {kind:"unavailable",code:"NATIVE_CANCEL_UNCERTAIN"}
    return {kind:response.status===403?"forbidden":"unavailable",code}
  }catch{return {kind:"unavailable",code:"NATIVE_CANCEL_UNCERTAIN"}}
}
