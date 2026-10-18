<script setup lang="ts">
import { computed, defineAsyncComponent, defineComponent, h, onBeforeUnmount, onMounted, ref, shallowRef, watch, type Component } from "vue"
import { useI18n } from "vue-i18n"
import { AlertTriangle, ArrowRight, Loader2, RefreshCw, ShieldCheck } from "lucide-vue-next"
import { ControlPanelShell } from "@/widgets/control-panel"
import { providerStateChanged } from "@/features/platform"
import { createSessionOpenRecovery, sessionOpenOwnerKey } from "@/features/agent-sessions"
import ProjectScopeSelector from "@/features/platform/ui/ProjectScopeSelector.vue"
import ControlPanelAccessPage from "@/pages/platform/ControlPanelAccessPage.vue"
import { OIDC_PRESENTATION_PAGES, resolveOidcView, countPresentableAgentSessionProjects, preferredAgentSessionProjectId, reconcileAgentSessionProjectId } from "@/features/platform/model/oidc-view-routing"
import { readRauthyPanelState, signOutRauthyPanel, type RauthyPanelIdentity, type RauthyPanelState } from "@/features/platform/api/rauthy-oidc"
import { readPlatformContext, readProjectContext, isPlatformProjectId, type VerifiedPlatformContext } from "@/features/platform/api/platform-current"
import type { ModuleId } from "@/features/modules/types"
import type { PlatformPageId } from "@/features/platform/types"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { Button } from "@/shared/ui/button"
import { Skeleton } from "@/shared/ui/skeleton"
import ProtectedSectionLoadState from "@/pages/platform/ProtectedSectionLoadState.vue"
import {boundedLifetime,type BoundedLifetime} from "@/shared/lib/bounded-lifetime"

/** Protected screens have NO reason to load during anonymous Rauthy
 * sign-in. Vue mounts them only when activeContext is an unexpired BFF
 * User+Project proof; code-splitting is presentation, NOT authorization.
 *
 * Missing/stale Dev chunks show a read-only retry, never a guessed owner.
 */
const ProtectedSectionLoadError=defineComponent({
  name:"ProtectedSectionLoadError",
  setup:()=>()=>h(ProtectedSectionLoadState,{failed:true}),
})
function protectedPage(loader:()=>Promise<{default:Component}>){
  return defineAsyncComponent({
    loader,
    delay:200,
    timeout:12000,
    loadingComponent:ProtectedSectionLoadState,
    errorComponent:ProtectedSectionLoadError,
  })
}
const OidcProjectWorkspace=protectedPage(()=>import("@/widgets/platform-context/ui/OidcProjectWorkspace.vue"))
const PlatformAdministration=protectedPage(()=>import("@/widgets/platform-context/ui/PlatformAdministration.vue"))
const CatalogWorkspace=protectedPage(()=>import("@/widgets/catalog/ui/CatalogWorkspace.vue"))
const ModuleWorkspacePage=protectedPage(()=>import("@/pages/modules/ModuleWorkspacePage.vue"))
const DashboardOverview=protectedPage(()=>import("@/widgets/dashboard/ui/DashboardOverview.vue"))
const PlatformSettingsPage=protectedPage(()=>import("@/pages/platform/PlatformSettingsPage.vue"))

/** First-class Rauthy cookie+PKCE application entry. Fresh, server-bound
 * Platform proof opens the panel layout, NOT a privileged PlatformPort.
 * All module descriptions/settings remain presentation-only unless a
 * separately verified per-action BFF endpoint exists.
 */
type AuthPhase="checking"|"signed_out"|"denied"|"unavailable"|"identity_only"|"verified"
const {t,locale}=useI18n()
const state=ref<AuthPhase>("checking")
const identity=ref<RauthyPanelIdentity|null>(null)
const providerSnapshot=ref<RauthyPanelState|null>(null)
const membership=ref<VerifiedPlatformContext|null>(null)
const selectedProjectId=ref<string|null>(null)
const focusedProjectId=ref<string|null>(null)
let focusedIdentity:string|null=null
const sessionOpenRecovery=createSessionOpenRecovery()
const revision=ref(0)
const route=ref<PlatformPageId>("home")
const refreshing=ref(false)
const loggingOut=ref(false)
const error=ref("")
const now=ref(Date.now())
// Presentation-only bounded lifetimes from independently verified BFF facts.
// A wall-clock rollback cannot stretch an already acquired owner lease.
const userLease=shallowRef<BoundedLifetime|null>(null)
const projectLease=shallowRef<BoundedLifetime|null>(null)
let controller:AbortController|null=null
let deadline:ReturnType<typeof setTimeout>|null=null
let nextRefresh:ReturnType<typeof setTimeout>|null=null
let clock:ReturnType<typeof setInterval>|null=null
let lastCheckedAt=0
const activeContext=computed(()=>{
  const proof=membership.value, user=identity.value
  return state.value==="verified"&&proof&&user&&
    proof.rauthy.subject===user.subject&&proof.rauthy.issuer===user.issuer&&
    Date.parse(proof.expires_at)>now.value&&Date.parse(user.expires_at)>now.value&&
    (projectLease.value?.remainingMilliseconds()??0)>0&&
    (userLease.value?.remainingMilliseconds()??0)>0
    ? proof:null
})
const activePage=computed<PlatformPageId>(()=>resolveOidcView("#platform/"+route.value,!!activeContext.value))
const labels=computed(()=>locale.value==="ru"?{
  verified:"Пользователь Briareus подтверждён сервером",
  fetching:"Проверяем сеанс и права доступа…",
  blocked:"Текущая учётная запись Rauthy не имеет подтверждённого доступа Briareus",
  unavailable:"Источник Platform-пользователей пока недоступен; серверные действия закрыты",
  unknown:"Проверка прав завершилась без подтверждённого результата",
  noData:"Данные и действия этого раздела требуют отдельного авторизованного Backend API",
  safe:"Это интерфейс раздела. Сама навигация не подтверждает разрешение выполнять операции.",
  retry:"Повторить проверку",logoutError:"Сервер не подтвердил завершение сеанса. Состояние может быть неизвестным.",
  user:"Пользователь",operator:"Оператор",
  next:"Следующий шаг",sessions:"Работа с AgentSession",
  sessionsHint:"Просмотр действующих сеансов, согласований и разрешённых действий выбранного проекта.",
  enterSessions:"Открыть AgentSession",
  noSessions:"Сервер пока не подтвердил ни одного проекта с доступом к AgentSession.",
}:{
  verified:"Briareus user confirmed by server",
  fetching:"Checking session and current permissions…",
  blocked:"This Rauthy account has no verified Briareus access",
  unavailable:"Platform identity service unavailable; server operations stay disabled",
  unknown:"Server did not verify current privileges",
  noData:"Records and actions in this area require a separate authorized Backend API",
  safe:"This is a section layout; navigating here does not authorize any operation.",
  retry:"Check again",logoutError:"Session revocation was not confirmed. Its state may be unknown.",
  user:"User",operator:"Operator",
  next:"Next step",sessions:"AgentSession workspace",
  sessionsHint:"Review current sessions, approvals, and authorized actions for a selected Project.",
  enterSessions:"Open AgentSessions",
  noSessions:"Server has not verified any Project with AgentSession access.",
})
const heading=computed(()=>t(`platform.navigation.${activePage.value==="browser-managed"?"browserManaged":activePage.value==="browser-external"?"browserExternal":activePage.value}`))
const moduleForPage:Partial<Record<PlatformPageId,ModuleId>>={
  files:"files",terminal:"terminal",
  "browser-managed":"web","browser-external":"web",analysis:"analysis",
  calls:"calls",oauth:"oauth",
}
const currentModule=computed(()=>moduleForPage[activePage.value]??null)
const actionableProjectCount=computed(()=>countPresentableAgentSessionProjects(
  activeContext.value?.projects??[],
))
const filesProjectReady=computed(()=>activeContext.value?.projects.some(project=>
  project.id===selectedProjectId.value&&project.permissions.includes("use_resources"))??false)
function selectProject(id:string):void {
  if(activeContext.value?.projects.some(project=>project.id===id))selectedProjectId.value=id
}
function openAgentSessions():void{
  const context=activeContext.value
  if(!context||actionableProjectCount.value===0)return
  if(!context.projects.some(project=>project.id===selectedProjectId.value&&
    (project.permissions.includes("use_resources")||project.permissions.includes("approve_agent_session")))){
    selectedProjectId.value=preferredAgentSessionProjectId(context.projects)
  }
  window.location.hash="platform/sessions"
}


function cancelRequests():void{
  controller?.abort()
  controller=null
  if(deadline!==null){clearTimeout(deadline);deadline=null}
  if(nextRefresh!==null){clearTimeout(nextRefresh);nextRefresh=null}
}
function hideAccess():void {
  projectLease.value=null;userLease.value=null
  identity.value=null
  membership.value=null
  selectedProjectId.value=null
  route.value="home"
  if(location.hash!=="#platform/home"){
    history.replaceState(null,"",`${location.pathname}${location.search}#platform/home`)
  }
}
function syncRoute():void{
  const next=resolveOidcView(location.hash,!!activeContext.value)
  route.value=next
  if(location.hash.split("/")[1]!==next||!location.hash.startsWith("#platform/")){
    if(next==="home")history.replaceState(null,"",`${location.pathname}${location.search}#platform/home`)
  }
}

async function selectProjectScope(id:string|null):Promise<void>{
  if(loggingOut.value||providerSnapshot.value?.kind!=="signed_in"||
    (id!==null&&!isPlatformProjectId(id)))return
  focusedProjectId.value=id
  const provider=providerSnapshot.value.identity
  focusedIdentity=id===null?null:JSON.stringify([provider.issuer,provider.subject,provider.client_id])
  // Unmount commands from the old Project before asking the new owner.
  // Never merge a point proof into the separately bounded inventory.
  state.value="checking";membership.value=null;selectedProjectId.value=null
  await refresh()
}
async function refresh():Promise<void>{
  if(loggingOut.value)return
  cancelRequests()
  const request=new AbortController(),run=++revision.value
  controller=request
  lastCheckedAt=Date.now()
  let targetProject=focusedProjectId.value
  refreshing.value=true
  error.value=""
  // Keep an existing denied/unavailable login screen mounted on retry.
  // Replacing it with an entire skeleton would cause a visible layout jump.
  deadline=setTimeout(()=>request.abort(),8500)
  try{
    const session=await readRauthyPanelState(request.signal)
    if(run!==revision.value||request.signal.aborted)return
    providerSnapshot.value=session
    if(session.kind!=="signed_in"){
      if(session.kind==="signed_out"){sessionOpenRecovery.clear();focusedProjectId.value=null;focusedIdentity=null}
      hideAccess()
      state.value=session.kind==="signed_out"?"signed_out":"unavailable"
      return
    }
    if(targetProject!==null&&focusedIdentity!==JSON.stringify([
      session.identity.issuer,session.identity.subject,session.identity.client_id,
    ])){
      focusedProjectId.value=null;focusedIdentity=null;targetProject=null
    }
    if(identity.value&&(identity.value.subject!==session.identity.subject||
      identity.value.issuer!==session.identity.issuer||
      identity.value.client_id!==session.identity.client_id)){
      // New Rauthy principal: hide the previous User's Project metadata
      // before starting the new (potentially slow) Platform owner lookup.
      focusedProjectId.value=null;focusedIdentity=null;targetProject=null
      hideAccess()
      state.value="checking"
    }
    const current=targetProject===null
      ?await readPlatformContext(session.identity,request.signal)
      :await readProjectContext(session.identity,targetProject,request.signal)
    if(run!==revision.value||request.signal.aborted)return
    if(current.kind==="verified"){
      const nextProjectLease=boundedLifetime(Date.parse(current.context.expires_at))
      const nextUserLease=boundedLifetime(Date.parse(session.identity.expires_at))
      if(!(nextProjectLease.remainingMilliseconds()>0&&nextUserLease.remainingMilliseconds()>0)){
        hideAccess();state.value="unavailable";return
      }
      sessionOpenRecovery.retainOwner(sessionOpenOwnerKey(
        session.identity.issuer,session.identity.subject,session.identity.client_id,current.context.user.id,
      ))
      const samePrincipal=identity.value?.issuer===session.identity.issuer&&
        identity.value?.subject===session.identity.subject&&
        membership.value?.user.id===current.context.user.id
      selectedProjectId.value=reconcileAgentSessionProjectId(
        samePrincipal?selectedProjectId.value:null,current.context.projects,
      )
      userLease.value=nextUserLease;projectLease.value=nextProjectLease
      identity.value=session.identity
      membership.value=current.context
      now.value=Date.now()
      state.value="verified"
      syncRoute()
      const remaining=Date.parse(current.context.expires_at)-Date.now()
      // Reverify before the 30s server proof expires; UI cannot extend it.
      nextRefresh=setTimeout(()=>{void refresh()},Math.max(1000,Math.min(remaining-4000,15000)))
      return
    }
    hideAccess()
    state.value=current.kind==="expired"||current.kind==="signed_out"?"signed_out":
      current.kind==="denied"||current.kind==="not_current"?"denied":
      current.kind==="unavailable"?"unavailable":"identity_only"
  }catch{
    if(run===revision.value){
      hideAccess()
      state.value="unavailable"
      providerSnapshot.value={kind:"unavailable",reason:"network"}
    }
  }finally{
    if(run===revision.value){
      if(request.signal.aborted){
        hideAccess()
        state.value="unavailable"
        providerSnapshot.value={kind:"unavailable",reason:"network"}
      }
      if(deadline!==null){clearTimeout(deadline);deadline=null}
      refreshing.value=false
      controller=null
    }
  }
}
async function logout():Promise<void>{
  if(loggingOut.value||(!activeContext.value&&providerSnapshot.value?.kind!=="signed_in"))return
  loggingOut.value=true
  sessionOpenRecovery.clear();focusedProjectId.value=null;focusedIdentity=null
  cancelRequests()
  const run=++revision.value
  refreshing.value=false
  error.value=""
  providerSnapshot.value=null
  // Close all action widgets before waiting for the logout response.
  // A live cookie during server IO is not permission to issue more commands.
  hideAccess()
  state.value="checking"
  const request=new AbortController()
  controller=request
  deadline=setTimeout(()=>request.abort(),8500)
  try{
    const result=await signOutRauthyPanel(request.signal)
    if(run!==revision.value)return
    if(result.kind==="revoked"&&!request.signal.aborted){
      providerSnapshot.value={kind:"signed_out"}
      hideAccess()
      state.value="signed_out"
    }else{
      // A prior verified User snapshot must never survive uncertain logout.
      providerSnapshot.value={kind:"unavailable",reason:"session_unavailable"}
      hideAccess()
      state.value="unavailable"
      error.value=labels.value.logoutError
    }
  }finally{
    if(run===revision.value){
      if(deadline!==null){clearTimeout(deadline);deadline=null}
      controller=null;loggingOut.value=false
    }
  }
}
function onLoginProviderState(value:RauthyPanelState|{kind:"checking"}):void {
  if(loggingOut.value||value.kind==="checking"||!providerStateChanged(providerSnapshot.value,value))return
  providerSnapshot.value=value
  if(value.kind==="signed_out"||value.kind==="unavailable"){
    // Invalidate an older /me before it can reopen the previous User's UI.
    if(value.kind==="signed_out"){sessionOpenRecovery.clear();focusedProjectId.value=null;focusedIdentity=null}
    ++revision.value
    cancelRequests()
    refreshing.value=false
    hideAccess()
    state.value=value.kind
    return
  }
  // A changed Rauthy identity still needs independent Platform ownership.
  void refresh()
}
function onVisibility():void{
  now.value=Date.now()
  if(document.visibilityState==="visible"&&Date.now()-lastCheckedAt>5000)void refresh()
}
function onHash():void{syncRoute()}
watch(activeContext,next=>{
  if(!next){
    if(state.value==="checking")return
    if(state.value==="verified"){
      // The short server proof expired even if a refresh did not complete.
      // Do not keep verified presentation controls mounted on stale evidence.
      providerSnapshot.value={kind:"unavailable",reason:"session_unavailable"}
      hideAccess()
      state.value="unavailable"
    }
    syncRoute()
  }
})
onMounted(()=>{
  // Preserve a requested deep link during the *initial* authentication check.
  // No protected component mounts until the BFF accepts current membership.
  route.value=resolveOidcView(location.hash,true)
  clock=setInterval(()=>{now.value=Date.now()},1000)
  window.addEventListener("hashchange",onHash)
  window.addEventListener("popstate",onHash)
  document.addEventListener("visibilitychange",onVisibility)
  void refresh()
})
onBeforeUnmount(()=>{
  sessionOpenRecovery.clear()
  ++revision.value
  cancelRequests()
  if(clock!==null)clearInterval(clock)
  window.removeEventListener("hashchange",onHash)
  window.removeEventListener("popstate",onHash)
  document.removeEventListener("visibilitychange",onVisibility)
  identity.value=null;membership.value=null;selectedProjectId.value=null;focusedProjectId.value=null;focusedIdentity=null
})
</script>

<template>
  <ControlPanelShell :page="activePage" :heading="heading"
    :authenticated="!!activeContext" :busy="loggingOut"
    :presentation-pages="activeContext?OIDC_PRESENTATION_PAGES:undefined"
    :presentation-only="!!activeContext" @logout="logout">
    <div v-if="error" role="alert" class="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{{error}}</div>
    <ProjectScopeSelector v-if="providerSnapshot?.kind==='signed_in'&&!loggingOut"
      :focused-project-id="focusedProjectId" :busy="refreshing" @select="selectProjectScope"/>
    <div v-if="activeContext&&identity" class="space-y-5">
      <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border bg-muted/30 px-4 py-3">
        <div class="flex min-w-0 flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <ShieldCheck class="size-4 text-primary" aria-hidden="true"/>
          <span class="font-medium text-foreground">{{labels.verified}}</span>
          <Badge variant="outline">{{activeContext.user.role==="operator"?labels.operator:labels.user}}</Badge>
          <Button type="button" variant="ghost" size="icon" class="size-8"
            :disabled="refreshing" :aria-label="labels.retry" :title="labels.retry" @click="refresh">
            <RefreshCw class="size-4" :class="refreshing?'animate-spin':''" aria-hidden="true"/>
          </Button>
          <span v-if="refreshing" class="text-[11px]">{{labels.fetching}}</span>
        </div>
      </div>

      <template v-if="activePage==='home'">
        <PlatformAdministration v-if="activeContext.user.role==='operator'" :context="activeContext" view="overview" @changed="refresh"/>
        <OidcProjectWorkspace :session-open-recovery="sessionOpenRecovery" :context="activeContext" :identity="identity" :selected-project-id="selectedProjectId" view="overview" @select-project="selectProject"/>
        <Card class="min-w-0">
          <CardHeader>
            <CardTitle class="text-base">{{labels.next}} · {{labels.sessions}}</CardTitle>
          </CardHeader>
          <CardContent class="flex flex-wrap items-center justify-between gap-3">
            <p class="max-w-xl text-sm text-muted-foreground">
              {{actionableProjectCount?labels.sessionsHint:labels.noSessions}}
            </p>
            <Button type="button" :disabled="!actionableProjectCount" @click="openAgentSessions">
              {{labels.enterSessions}} <ArrowRight class="ml-2 size-4" aria-hidden="true"/>
            </Button>
          </CardContent>
        </Card>
      </template>
      <PlatformAdministration v-else-if="activeContext.user.role==='operator'&&(activePage==='users'||activePage==='teams'||activePage==='projects')" :key="activePage" :context="activeContext" :view="activePage" @changed="refresh"/>
      <OidcProjectWorkspace :session-open-recovery="sessionOpenRecovery" v-else-if="activePage==='users'||activePage==='teams'||activePage==='projects'" :context="activeContext" :identity="identity" :selected-project-id="selectedProjectId" :view="activePage==='users'?'overview':activePage" @select-project="selectProject"/>
      <OidcProjectWorkspace :session-open-recovery="sessionOpenRecovery" v-else-if="activePage==='sessions'" :context="activeContext" :identity="identity" :selected-project-id="selectedProjectId" view="sessions" @select-project="selectProject"/>
      <CatalogWorkspace v-else-if="activePage==='integrations'" :context="activeContext" :selected-project-id="selectedProjectId" kind="integration" @select-project="selectProject"/>
      <CatalogWorkspace v-else-if="activePage==='variables'" :context="activeContext" :selected-project-id="selectedProjectId" kind="variable" @select-project="selectProject"/>
      <ModuleWorkspacePage v-else-if="activePage==='mcp'" :files-project-can-request="filesProjectReady" :files-identity="identity" :files-context="activeContext" :files-project-id="selectedProjectId" @open-sessions="openAgentSessions"/>
      <ModuleWorkspacePage v-else-if="currentModule" :key="activePage" :initial="currentModule"
        :files-project-can-request="filesProjectReady" :files-identity="identity" :files-context="activeContext" :files-project-id="selectedProjectId" @open-sessions="openAgentSessions"/>
      <DashboardOverview v-else-if="activePage==='dashboard'" state="unavailable"/>
      <PlatformSettingsPage v-else-if="activePage==='settings'"/>
      <Card v-else>
        <CardHeader><CardTitle class="text-base">{{heading}}</CardTitle></CardHeader>
        <CardContent class="space-y-3">
          <AlertTriangle class="size-5 text-muted-foreground" aria-hidden="true"/>
          <p class="text-sm text-muted-foreground">{{labels.noData}}</p>
          <p class="text-xs text-muted-foreground">{{labels.safe}}</p>
        </CardContent>
      </Card>
    </div>
    <div v-else-if="state==='checking'" class="mx-auto max-w-3xl space-y-4 py-8" role="status">
      <div class="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 class="size-4 animate-spin" aria-hidden="true"/>{{labels.fetching}}
      </div>
      <Skeleton class="h-56 w-full"/>
      <Skeleton class="h-16 w-full"/>
    </div>
    <div v-else>
      <div v-if="state==='denied'||state==='identity_only'||state==='unavailable'"
        class="mx-auto mb-4 flex max-w-4xl items-start justify-between gap-3 rounded-lg border border-border bg-muted/20 p-3" role="status">
        <span class="text-sm text-muted-foreground">{{state==='denied'?labels.blocked:state==='unavailable'?labels.unavailable:labels.unknown}}</span>
        <Button size="sm" variant="outline" :disabled="refreshing" @click="refresh">
          <Loader2 v-if="refreshing" class="mr-1 size-4 animate-spin" aria-hidden="true"/>
          {{labels.retry}}
        </Button>
      </div>
      <ControlPanelAccessPage :initial-session="providerSnapshot" managed-logout
        @logout-requested="logout" @provider-state="onLoginProviderState"/>
    </div>
  </ControlPanelShell>
</template>
