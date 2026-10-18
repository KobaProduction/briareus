<script setup lang="ts">
import { computed, ref, watch } from "vue"
import { sessionOpenOwnerKey, type SessionOpenRecovery } from "@/features/agent-sessions"
import { useI18n } from "vue-i18n"
import { FolderKanban, ShieldAlert, UsersRound } from "lucide-vue-next"
import type { RauthyPanelIdentity } from "@/features/platform/api/rauthy-oidc"
import { readProjectContext, type VerifiedPlatformContext } from "@/features/platform/api/platform-current"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { Button } from "@/shared/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/shared/ui/tabs"
import ApprovalQueue from "./ApprovalQueue.vue"
import CurrentAgentSessions from "./CurrentAgentSessions.vue"
import OpenNormalSession from "./OpenNormalSession.vue"

/** Composition after actual Rauthy+Platform proof; never installs a fake
 * PlatformPort or unlocks other legacy management operations. */
const props=withDefaults(defineProps<{
  identity:RauthyPanelIdentity
  context:VerifiedPlatformContext
  selectedProjectId:string|null
  sessionOpenRecovery:SessionOpenRecovery
  view?:"overview"|"teams"|"projects"|"sessions"
}>(),{view:"overview"})
const emit=defineEmits<{selectProject:[id:string]}>()
const {locale}=useI18n()
const sessionTab=ref<"current"|"approvals"|"open">("current")
function selectProject(id:string):void {
  if(!props.context.projects.some(project=>project.id===id))return
  emit("selectProject",id)
  sessionTab.value="current"
}
function selectSessionTab(value:unknown):void {
  if(value==="current"||value==="approvals"||value==="open")sessionTab.value=value
}
const words=computed(()=>locale.value==="ru"?{
  account:"Учётная запись и области",actor:"Platform User",teams:"Команды",
  projects:"Проекты",user:"Пользователь",operator:"Оператор",
  none:"Нет подтверждённых записей",owner:"Владелец",member:"Участник",
  rights:"Разрешения",use:"Использование ресурсов",approve:"Одобрение AgentSession",
  selected:"Выбранный проект",absence:"Нет подтверждённых полномочий на операции в этом проекте",
  sessions:"Текущие сеансы",approvals:"Согласования",open:"Создать сеанс",
  only:"Названия и права подтверждены сервером",
  noWrites:"Управление командами и проектами доступно оператору в соответствующих разделах",
}:{
  account:"Account and scopes",actor:"Platform user",teams:"Teams",
  projects:"Projects",user:"User",operator:"Operator",none:"No verified records",
  owner:"Owner",member:"Member",rights:"Permissions",use:"Use resources",
  approve:"Approve AgentSession",selected:"Selected project",
  absence:"No verified action rights for this project",
  sessions:"Current sessions",approvals:"Approvals",open:"Create session",
  only:"Names and permissions are verified by the server",
  noWrites:"Operators can manage teams and projects in their respective sections",
})
const openOwnerKey=computed(()=>sessionOpenOwnerKey(
  props.identity.issuer,props.identity.subject,props.identity.client_id,props.context.user.id,
))
const chosen=computed(()=>props.context.projects.find(p=>p.id===props.selectedProjectId)??null)
watch(()=>props.selectedProjectId,()=>{sessionTab.value="current"})
async function verify(action:"use_resources"|"approve_agent_session",signal:AbortSignal):Promise<"authorized"|"unauthorized"|"forbidden"|"unavailable">{
  const previous=props.context
  const project=chosen.value
  if(!project||!project.permissions.includes(action))return "forbidden"
  const live=await readProjectContext(props.identity,project.id,signal)
  if(live.kind==="expired"||live.kind==="signed_out")return "unauthorized"
  if(live.kind==="not_current"||live.kind==="denied")return "forbidden"
  if(live.kind!=="verified")return "unavailable"
  const current=live.context
  return current.user.id===previous.user.id &&
    current.rauthy.issuer===props.identity.issuer &&
    current.rauthy.subject===props.identity.subject &&
    current.projects.some(p=>p.id===project.id&&p.permissions.includes(action))
    ?"authorized":"forbidden"
}
const verifyResource=(signal:AbortSignal)=>verify("use_resources",signal)
const verifyApprover=(signal:AbortSignal)=>verify("approve_agent_session",signal)
</script>

<template>
  <div class="space-y-5">
    <Card v-if="view==='overview' || view==='teams'" class="min-w-0">
      <CardHeader>
        <CardTitle class="flex items-center gap-2 text-base">
          <UsersRound class="size-5" aria-hidden="true"/>{{view==='overview'?words.account:words.teams}}
        </CardTitle>
      </CardHeader>
      <CardContent class="space-y-4">
        <div v-if="view==='overview'" class="flex flex-wrap items-center gap-3">
          <span class="font-medium text-foreground" :title="context.user.id">{{context.user.name||context.user.email||words.user}}</span>
          <Badge variant="outline">{{context.user.role==='operator'?words.operator:words.user}}</Badge>
        </div>
        <p class="text-xs font-semibold uppercase text-muted-foreground">{{words.teams}} ({{context.teams.length}})</p>
        <p v-if="!context.teams.length" class="rounded-lg border border-dashed border-border px-4 py-6 text-sm text-muted-foreground">{{words.none}}</p>
        <div v-else class="grid gap-2 sm:grid-cols-2">
          <div v-for="team in context.teams" :key="team.id" class="min-w-0 rounded-lg border border-border bg-muted/10 p-3">
            <p class="font-medium" :title="team.id">{{team.name||words.teams}}</p>
            <p class="mt-2 text-xs text-muted-foreground">{{team.owner?words.owner:words.member}}</p>
          </div>
        </div>
        <p class="text-xs text-muted-foreground">{{words.noWrites}}</p>
      </CardContent>
    </Card>

    <Card v-if="view==='overview'||view==='projects'||view==='sessions'" class="min-w-0">
      <CardHeader :class="view==='sessions'?'pb-3':''"><CardTitle class="flex items-center gap-2 text-base">
        <FolderKanban class="size-5" aria-hidden="true"/>{{words.projects}} ({{context.projects.length}})
      </CardTitle></CardHeader>
      <CardContent>
        <p v-if="!context.projects.length" class="rounded-lg border border-dashed border-border p-5 text-sm text-muted-foreground">{{words.none}}</p>
        <div v-else class="flex flex-wrap gap-2" role="group" :aria-label="words.selected">
          <Button v-for="project in context.projects" :key="project.id" type="button" size="sm"
            :variant="selectedProjectId===project.id?'default':'outline'" :aria-pressed="selectedProjectId===project.id"
            :title="project.id" @click="selectProject(project.id)">
            {{project.name||words.projects}}
          </Button>
        </div>
        <div v-if="chosen" class="mt-3 rounded-xl border border-border bg-muted/20 p-3"
          :class="view==='sessions'?'space-y-2':'space-y-3 sm:p-4'">
          <p class="font-medium" :title="chosen.id">{{chosen.name||words.projects}}</p>
          <p v-if="view!=='sessions'" class="text-xs text-muted-foreground">{{words.owner}}: {{chosen.owner.kind==='user'?(context.user.name||context.user.email||words.user):(context.teams.find(t=>t.id===chosen?.owner.id)?.name||words.teams)}}</p>
          <p class="text-xs text-muted-foreground">{{words.rights}}</p>
          <div class="flex flex-wrap gap-2">
            <Badge v-for="permission in chosen.permissions" :key="permission" variant="outline">
              {{permission==='use_resources'?words.use:words.approve}}
            </Badge>
            <p v-if="!chosen.permissions.length" class="text-xs text-muted-foreground">{{words.absence}}</p>
          </div>
        </div>
      </CardContent>
    </Card>

    <Tabs v-if="view==='sessions'&&chosen?.permissions.some(right=>right==='use_resources'||right==='approve_agent_session')"
      :model-value="sessionTab" class="min-w-0 space-y-3" @update:model-value="selectSessionTab">
      <TabsList class="flex min-h-11 w-full flex-nowrap justify-start gap-1 overflow-x-auto p-1 sm:w-fit"
        :aria-label="words.sessions">
        <TabsTrigger value="current" class="min-h-9 shrink-0 whitespace-nowrap">{{words.sessions}}</TabsTrigger>
        <TabsTrigger value="approvals" class="min-h-9 shrink-0 whitespace-nowrap">{{words.approvals}}</TabsTrigger>
        <TabsTrigger v-if="chosen.permissions.includes('use_resources')" value="open"
          class="min-h-9 shrink-0 whitespace-nowrap">{{words.open}}</TabsTrigger>
      </TabsList>
      <TabsContent value="current" class="min-w-0">
        <CurrentAgentSessions v-if="sessionTab==='current'" :key="'current-'+chosen.id"
          :project-id="chosen.id" :actor-id="context.user.id" :proof-expires-at="context.expires_at"
          :can-list="true" :can-approve="chosen.permissions.includes('approve_agent_session')"
          :verify-approver="verifyApprover"/>
      </TabsContent>
      <TabsContent value="approvals" class="min-w-0">
        <ApprovalQueue v-if="sessionTab==='approvals'" :key="'approvals-'+chosen.id"
          :project-id="chosen.id" :actor-id="context.user.id" :proof-expires-at="context.expires_at"
          :can-read="true" :can-approve="chosen.permissions.includes('approve_agent_session')"
          :verify-approver="verifyApprover"/>
      </TabsContent>
      <TabsContent v-if="chosen.permissions.includes('use_resources')" value="open" class="min-w-0">
        <OpenNormalSession v-if="sessionTab==='open'" :key="'open-'+chosen.id"
          :project-id="chosen.id" :actor-id="context.user.id" :proof-expires-at="context.expires_at"
          :can-open="true" :can-approve="chosen.permissions.includes('approve_agent_session')" :verify-user="verifyResource" :recovery="sessionOpenRecovery" :owner-key="openOwnerKey"/>
      </TabsContent>
    </Tabs>
    <p v-else-if="view==='sessions'" class="flex items-start gap-2 rounded-xl border border-border bg-muted/30 p-4 text-sm text-muted-foreground" role="status">
      <ShieldAlert class="mt-0.5 size-4 shrink-0"/>{{words.absence}}
    </p>
    <p class="text-xs text-muted-foreground">{{words.only}}</p>
  </div>
</template>
