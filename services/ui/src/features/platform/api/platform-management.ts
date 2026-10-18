import {readBoundedJsonResponse} from "@/shared/lib/bounded-json-response"

export interface PlatformPerson {id:string;name:string|null;email:string|null;role:"user"|"operator";enabled:boolean}
export interface ManagedTeam {id:string;name:string;owner_user_id:string;member_ids:string[]}
export interface ManagedProject {id:string;name:string;owner_user_id:string|null;owner_team_id:string|null}
export interface PlatformInventory {users:PlatformPerson[];teams:ManagedTeam[];projects:ManagedProject[];truncated:boolean}
export type ManagementAction="team.create"|"team.rename"|"team.member.add"|"team.member.remove"|"project.create"|"project.rename"|"user.link"
export interface PlatformCommand {operation_uuid:string;action:ManagementAction;data:Record<string,unknown>}
export class PlatformCommandFailure extends Error {
  constructor(public code:string,public uncertain:boolean){super(code)}
}
export async function platformInventory(signal:AbortSignal):Promise<PlatformInventory>{
  const response=await fetch("/api/v1/platform/inventory",{credentials:"same-origin",mode:"same-origin",redirect:"error",cache:"no-store",signal,headers:{Accept:"application/json"}})
  const body=await readBoundedJsonResponse(response,signal,262144) as PlatformInventory&{error?:{code:string}}
  if(!response.ok)throw new PlatformCommandFailure(body.error?.code||"UNAVAILABLE",false)
  if(!Array.isArray(body.users)||!Array.isArray(body.teams)||!Array.isArray(body.projects)||body.users.length>100||body.teams.length>100||body.projects.length>100)throw new Error("Invalid inventory")
  return body
}
export async function platformCommand(command:PlatformCommand,signal:AbortSignal):Promise<void>{
  let response:Response
  try{
    response=await fetch("/api/v1/platform/commands",{method:"POST",credentials:"same-origin",mode:"same-origin",redirect:"error",cache:"no-store",signal,headers:{"Content-Type":"application/json",Accept:"application/json"},body:JSON.stringify(command)})
  }catch{throw new PlatformCommandFailure("NETWORK_UNAVAILABLE",true)}
  let body:{error?:{code:string}}
  try{body=await readBoundedJsonResponse(response,signal,262144) as typeof body}
  catch{throw new PlatformCommandFailure("INVALID_RESPONSE",true)}
  if(!response.ok)throw new PlatformCommandFailure(body.error?.code||"UNAVAILABLE",response.status>=500)
}
