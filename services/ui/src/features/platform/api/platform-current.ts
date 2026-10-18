import {readBoundedJsonResponse,readBoundedErrorCode} from "@/shared/lib/bounded-json-response"
import {CONTROL_PANEL_AUTH_API} from "@/shared/config/control-panel-api"
import type { RauthyPanelIdentity } from "@/features/platform/api/rauthy-oidc"

/** Exact SOURCE contract: services/api/src/control_panel_api/_oidc_membership.py.
 * GET /api/v1/auth/me is cookie-bound and may correctly remain 503 until the
 * Backend installs a trusted Platform owner adapter. No PlatformPort is minted.
 */
export type ProjectPermission = "use_resources" | "approve_agent_session"
export interface PlatformTeamProof { id: string; owner: boolean; name?:string|null }
export interface PlatformProjectProof {
  id: string
  name?:string|null
  owner: {kind:"user" | "team";id:string}
  permissions: ProjectPermission[]
}
export interface VerifiedPlatformContext {
  authenticated: true
  authority: "platform"
  rauthy: { issuer: string; subject: string }
  user: {id:string;role:"user" | "operator";enabled:true;name?:string|null;email?:string|null}
  teams: PlatformTeamProof[]
  projects: PlatformProjectProof[]
  expires_at: string
}
export type PlatformContextState =
  | { kind:"verified"; context:VerifiedPlatformContext }
  | { kind:"signed_out" | "expired" | "denied" | "not_current" }
  | { kind:"unavailable"; code:string }
  | { kind:"invalid_response" }

const ROUTE=CONTROL_PANEL_AUTH_API+"/me"
const UUID4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
function obj(value:unknown):Record<string,unknown>|null {
  return value!==null&&typeof value==="object"&&!Array.isArray(value)
    ?value as Record<string,unknown>:null
}
export function isPlatformProjectId(value:unknown):value is string {
  return typeof value==="string"&&UUID4.test(value)
}
function asUuid(value:unknown):string|null {return isPlatformProjectId(value)?value:null}
function validate(value:unknown, identity:RauthyPanelIdentity):VerifiedPlatformContext|null {
  const v=obj(value)
  if(!v||v.authenticated!==true||v.authority!=="platform")return null
  const ext=obj(v.rauthy), user=obj(v.user)
  if(!ext||ext.subject!==identity.subject||ext.issuer!==identity.issuer||
    !user||!asUuid(user.id)||user.enabled!==true||
    (user.role!=="user"&&user.role!=="operator")||
    !Array.isArray(v.teams)||v.teams.length>100||
    !Array.isArray(v.projects)||v.projects.length>100||
    typeof v.expires_at!=="string")return null
  // Backend requires a timezone-aware instant, not a browser-local date.
  if(!/(?:Z|[+-][0-2][0-9]:[0-5][0-9])$/.test(v.expires_at))return null
  const expires=Date.parse(v.expires_at)
  // Backend guarantees freshness <=30s; fail closed on expired or implausible proofs.
  if(!Number.isFinite(expires)||expires<=Date.now()||
    expires>Date.now()+31000||expires>Date.parse(identity.expires_at))return null
  const teams:PlatformTeamProof[]=[]
  const seenTeams=new Set<string>()
  for(const t of v.teams){
    const row=obj(t)
    if(!row||!asUuid(row.id)||seenTeams.has(row.id as string)||
      typeof row.owner!=="boolean")return null
    seenTeams.add(row.id as string)
    if(row.name!==undefined&&row.name!==null&&(typeof row.name!=="string"||row.name.length>255))return null
    teams.push({id:row.id as string,owner:row.owner,name:row.name as string|null|undefined})
  }
  const projects:PlatformProjectProof[]=[]
  const seenProjects=new Set<string>()
  for(const p of v.projects){
    const row=obj(p),owner=obj(row?.owner)
    if(!row||!owner||!asUuid(row.id)||seenProjects.has(row.id as string)||
      !asUuid(owner.id)||(owner.kind!=="user"&&owner.kind!=="team")||
      (owner.kind==="user"&&owner.id!==user.id)||
      (owner.kind==="team"&&!seenTeams.has(owner.id as string))||
      !Array.isArray(row.permissions)||row.permissions.length>2||
      new Set(row.permissions).size!==row.permissions.length||
      row.permissions.some(x=>x!=="use_resources"&&x!=="approve_agent_session")||
      (row.permissions.includes("approve_agent_session")&&
        user.role!=="operator"&&!(owner.kind==="user"&&owner.id===user.id)&&
        !teams.some(t=>t.id===owner.id&&t.owner)))return null
    seenProjects.add(row.id as string)
    if(row.name!==undefined&&row.name!==null&&(typeof row.name!=="string"||row.name.length>255))return null
    projects.push({id:row.id as string,name:row.name as string|null|undefined,
      owner:{kind:owner.kind,id:owner.id as string},
      permissions:[...row.permissions] as ProjectPermission[]})
  }
  return {authenticated:true,authority:"platform",
    rauthy:{issuer:identity.issuer,subject:identity.subject},
    user:{id:user.id as string,role:user.role as "user"|"operator",enabled:true,name:typeof user.name==="string"?user.name:undefined,email:typeof user.email==="string"?user.email:undefined},
    teams,projects,expires_at:v.expires_at}
}
async function readContext(
  identity:RauthyPanelIdentity,
  signal:AbortSignal,
  projectUuid?:string,
):Promise<PlatformContextState>{
  if(projectUuid!==undefined&&!asUuid(projectUuid))return {kind:"invalid_response"}
  if(signal.aborted)return {kind:"unavailable",code:"PLATFORM_READ_CANCELLED"}
  try {
    const response=await fetch(projectUuid===undefined?ROUTE:ROUTE+"?project_uuid="+projectUuid,{
      method:"GET",credentials:"same-origin",mode:"same-origin",signal,
      redirect:"error",cache:"no-store",referrerPolicy:"no-referrer",
      headers:{Accept:"application/json"},
    })
    if(signal.aborted)return {kind:"unavailable",code:"PLATFORM_READ_CANCELLED"}
    if(response.status===200){
      const proof=validate(await readBoundedJsonResponse(response,signal,262_144),identity)
      if(signal.aborted)return {kind:"unavailable",code:"PLATFORM_READ_CANCELLED"}
      if(!proof||projectUuid!==undefined&&(proof.projects.length!==1||
        proof.projects[0]?.id!==projectUuid||proof.teams.length>1))return {kind:"invalid_response"}
      return {kind:"verified",context:proof}
    }
    const code=await readBoundedErrorCode(response,signal)
    if(signal.aborted)return {kind:"unavailable",code:"PLATFORM_READ_CANCELLED"}
    if(response.status===401)return {kind:code==="OIDC_SESSION_EXPIRED"?"expired":"signed_out"}
    if(response.status===403)return {kind:code==="PLATFORM_MEMBERSHIP_NOT_CURRENT"?"not_current":"denied"}
    return {kind:"unavailable",code}
  }catch{return {kind:"unavailable",code:signal.aborted?"PLATFORM_READ_CANCELLED":"NETWORK_UNAVAILABLE"}}
}

/** Bounded navigation inventory; never a substitute for an exact Project
 * owner read immediately before a Project-scoped management command. */
export function readPlatformContext(identity:RauthyPanelIdentity,signal:AbortSignal):Promise<PlatformContextState>{
  return readContext(identity,signal)
}
/** Source-backed exact Project read added by Backend's membership router.
 * Do not fall back to the capped inventory if this request is unavailable. */
export function readProjectContext(identity:RauthyPanelIdentity,projectUuid:string,signal:AbortSignal):Promise<PlatformContextState>{
  return readContext(identity,signal,projectUuid)
}
