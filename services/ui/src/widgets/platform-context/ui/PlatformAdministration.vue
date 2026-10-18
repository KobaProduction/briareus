<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from "vue"
import {useI18n} from "vue-i18n"
import {Plus,RefreshCw,Pencil,UsersRound,FolderKanban,UserRound,X} from "lucide-vue-next"
import type {VerifiedPlatformContext} from "@/features/platform/api/platform-current"
import {platformCommand,platformInventory,PlatformCommandFailure,type PlatformCommand,type PlatformInventory,type ManagedTeam,type ManagedProject,type ManagementAction} from "@/features/platform/api/platform-management"
import {Button} from "@/shared/ui/button"
import {Input} from "@/shared/ui/input"
import {Badge} from "@/shared/ui/badge"
import {Card,CardHeader,CardTitle,CardContent} from "@/shared/ui/card"

const props=defineProps<{context:VerifiedPlatformContext;view:"overview"|"users"|"teams"|"projects"}>()
const emit=defineEmits<{changed:[]}>()
const {locale}=useI18n()
const ru=computed(()=>locale.value==="ru")
const inventory=ref<PlatformInventory|null>(null),loading=ref(false),busy=ref(false)
const error=ref(""),notice=ref(""),teamName=ref(""),projectName=ref(""),projectTeam=ref(""),email=ref("")
const selectedTeam=ref(""),selectedUser=ref("")
const editing=ref<{kind:"team"|"project";id:string;expected_name:string;name:string}|null>(null)
const pending=ref<PlatformCommand|null>(null)
let controller:AbortController|null=null,commandController:AbortController|null=null,revision=0
const operator=computed(()=>props.context.user.role==="operator")
const blocked=computed(()=>busy.value||pending.value!==null)
const team=computed(()=>inventory.value?.teams.find(t=>t.id===selectedTeam.value))
const candidates=computed(()=>inventory.value?.users.filter(u=>u.enabled&&!team.value?.member_ids.includes(u.id))??[])
const storageKey=()=>"briareus:platform-command:"+props.context.user.id
const person=(id:string)=>{const user=inventory.value?.users.find(u=>u.id===id);return user?.name||user?.email||(ru.value?"Пользователь":"User")}
const owner=(project:ManagedProject)=>project.owner_team_id?(inventory.value?.teams.find(t=>t.id===project.owner_team_id)?.name||(ru.value?"Команда":"Team")):person(project.owner_user_id||"")
const inputClass="h-9 rounded-md border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
const messages:Record<string,[string,string]>={
  NAME_REQUIRED:["Укажите название.","Enter a name."],NAME_INVALID:["Название должно содержать от 1 до 255 символов.","Use 1–255 characters."],
  NAME_CHANGED:["Запись уже изменена. Данные обновлены — повторите действие.","The record changed. Review refreshed data and try again."],
  RAUTHY_USER_NOT_FOUND:["Учётная запись с таким email не найдена в Rauthy.","No Rauthy account matches this email."],
  RAUTHY_USER_NOT_ACTIVE:["Учётная запись отключена или истекла.","The account is disabled or expired."],
  TEAM_OWNER_REQUIRED:["Владелец должен оставаться участником команды.","The owner must remain a team member."],
  PLATFORM_OPERATOR_REQUIRED:["Для управления нужна роль оператора.","Operator access is required."],
  USER_SUSPENDED:["Пользователь приостановлен в Platform.","The Platform user is suspended."],
}
function describe(value:unknown):string{
  const code=value instanceof PlatformCommandFailure?value.code:"UNAVAILABLE"
  return messages[code]?.[ru.value?0:1]||(ru.value?"Не удалось получить подтверждение сервера.":"The server could not confirm the operation.")
}
async function load():Promise<void>{
  controller?.abort();const request=new AbortController(),run=++revision
  controller=request;loading.value=true
  const timer=setTimeout(()=>request.abort(),8500)
  try{
    const result=await platformInventory(request.signal)
    if(run!==revision)return
    inventory.value=result
    if(!result.teams.some(t=>t.id===selectedTeam.value))selectedTeam.value=result.teams[0]?.id||""
  }catch(value){if(run===revision){error.value=describe(value);inventory.value=null}}
  finally{clearTimeout(timer);if(run===revision)loading.value=false}
}
function persist():void{
  try{if(pending.value)sessionStorage.setItem(storageKey(),JSON.stringify(pending.value));else sessionStorage.removeItem(storageKey())}catch{/* Memory still retains the original command for retry. */}
}
async function send(action:ManagementAction,data:Record<string,unknown>):Promise<void>{
  if(blocked.value)return
  pending.value={operation_uuid:crypto.randomUUID(),action,data};persist()
  await retry()
}
async function retry():Promise<void>{
  if(!pending.value||busy.value)return
  const command=pending.value,actor=props.context.user.id
  busy.value=true;error.value="";notice.value=""
  const request=new AbortController();commandController=request
  const timer=setTimeout(()=>request.abort(),8500)
  try{
    await platformCommand(command,request.signal)
    if(actor!==props.context.user.id)return
    pending.value=null;persist()
    teamName.value="";projectName.value="";email.value="";editing.value=null;selectedUser.value=""
    notice.value=ru.value?"Изменения сохранены.":"Changes saved."
    await load();emit("changed")
  }catch(value){
    if(actor!==props.context.user.id)return
    error.value=describe(value)
    if(!(value instanceof PlatformCommandFailure)||!value.uncertain){pending.value=null;persist();await load()}
  }finally{clearTimeout(timer);busy.value=false;commandController=null}
}
function edit(kind:"team"|"project",item:ManagedTeam|ManagedProject):void{editing.value={kind,id:item.id,expected_name:item.name,name:item.name}}
async function saveName():Promise<void>{const item=editing.value;if(!item?.name.trim())return;await send(item.kind==="team"?"team.rename":"project.rename",{id:item.id,expected_name:item.expected_name,name:item.name.trim()})}
watch(()=>props.context.user.id,()=>{
  controller?.abort();commandController?.abort();++revision
  inventory.value=null;pending.value=null;editing.value=null;error.value="";notice.value=""
  try{
    const saved=JSON.parse(sessionStorage.getItem(storageKey())||"null") as PlatformCommand|null
    if(saved&&typeof saved.operation_uuid==="string"&&typeof saved.action==="string"&&saved.data&&typeof saved.data==="object")pending.value=saved
  }catch{/* Corrupt browser state is never used as authority. */}
  if(operator.value)void load()
},{immediate:true})
onBeforeUnmount(()=>{controller?.abort();commandController?.abort();++revision})
</script>

<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 class="text-xl font-semibold">{{view==='users'?(ru?'Пользователи':'Users'):view==='teams'?(ru?'Команды':'Teams'):view==='projects'?(ru?'Проекты':'Projects'):(ru?'Рабочее пространство':'Workspace')}}</h2>
        <p class="mt-1 text-sm text-muted-foreground">{{context.user.name||context.user.email||(ru?'Пользователь':'User')}}</p>
      </div>
      <Button v-if="operator" variant="outline" :disabled="loading||busy" @click="error='';load()"><RefreshCw class="mr-2 size-4" :class="loading?'animate-spin':''"/>{{ru?'Обновить':'Refresh'}}</Button>
    </div>
    <p v-if="!operator" class="text-sm text-muted-foreground">{{ru?'Управление доступно оператору платформы.':'Management requires a Platform operator.'}}</p>
    <p v-if="error" role="alert" class="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{{error}}</p>
    <p v-if="notice" role="status" class="rounded-lg border border-border bg-muted/30 p-3 text-sm">{{notice}}</p>
    <div v-if="pending" class="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm" role="status">
      <p>{{ru?'Ожидаем подтверждения операции. При потере связи повторная отправка проверит исходную операцию и не создаст дубликат.':'Awaiting confirmation. Retrying checks the original operation without creating a duplicate.'}}</p>
      <Button class="mt-3" variant="outline" :disabled="busy" @click="retry">{{busy?(ru?'Сохраняем…':'Saving…'):(ru?'Повторить отправку':'Retry operation')}}</Button>
    </div>
    <p v-if="loading&&!inventory" role="status" class="text-sm text-muted-foreground">{{ru?'Загружаем данные…':'Loading…'}}</p>
    <template v-if="inventory&&operator">
      <p v-if="inventory.truncated" class="text-sm text-muted-foreground">{{ru?'Показаны первые 100 записей.':'Showing the first 100 records.'}}</p>
      <div v-if="view==='overview'" class="grid gap-4 sm:grid-cols-3">
        <Card v-for="stat in [{label:ru?'Пользователи':'Users',count:inventory.users.length,icon:UserRound},{label:ru?'Команды':'Teams',count:inventory.teams.length,icon:UsersRound},{label:ru?'Проекты':'Projects',count:inventory.projects.length,icon:FolderKanban}]" :key="stat.label"><CardContent class="flex items-center gap-4 p-5"><component :is="stat.icon" class="size-7 text-muted-foreground"/><div><p class="text-2xl font-semibold">{{stat.count}}</p><p class="text-sm text-muted-foreground">{{stat.label}}</p></div></CardContent></Card>
      </div>
      <Card v-if="view==='users'">
        <CardHeader><CardTitle>{{ru?'Пользователи платформы':'Platform users'}}</CardTitle></CardHeader>
        <CardContent class="space-y-5">
          <form class="flex flex-wrap items-end gap-3" @submit.prevent="send('user.link',{email:email.trim()})">
            <label class="min-w-56 flex-1 space-y-1 text-sm">Email<Input v-model="email" type="email" required maxlength="254" :disabled="blocked" :placeholder="ru?'Email существующей учётной записи':'Existing account email'"/></label>
            <Button type="submit" :disabled="blocked||!email.trim()"><Plus class="mr-2 size-4"/>{{ru?'Подключить пользователя':'Connect user'}}</Button>
          </form>
          <p class="text-xs text-muted-foreground">{{ru?'Подключается существующая учётная запись Rauthy с ролью пользователя. Пароли здесь не создаются и не изменяются.':'Connect an existing Rauthy account as a regular user. Credentials are managed by Rauthy.'}}</p>
          <div class="divide-y divide-border">
            <div v-for="user in inventory.users" :key="user.id" class="flex flex-wrap items-center justify-between gap-3 py-4">
              <div><p class="font-medium" :title="user.id">{{user.name||user.email||(ru?'Пользователь':'User')}}</p><p class="text-sm text-muted-foreground">{{user.email}}</p></div>
              <div class="flex gap-2"><Badge variant="outline">{{user.role==='operator'?(ru?'Оператор':'Operator'):(ru?'Пользователь':'User')}}</Badge><Badge v-if="!user.enabled" variant="secondary">{{ru?'Отключён':'Disabled'}}</Badge></div>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card v-if="view==='teams'">
        <CardHeader><CardTitle>{{ru?'Команды':'Teams'}}</CardTitle></CardHeader>
        <CardContent class="space-y-5">
          <form class="flex flex-wrap items-end gap-3" @submit.prevent="send('team.create',{name:teamName.trim()})">
            <label class="min-w-56 flex-1 space-y-1 text-sm">{{ru?'Название команды':'Team name'}}<Input v-model="teamName" required maxlength="255" :disabled="blocked" :placeholder="ru?'Например, Разработка':'For example, Engineering'"/></label>
            <Button type="submit" :disabled="blocked||!teamName.trim()"><Plus class="mr-2 size-4"/>{{ru?'Создать команду':'Create team'}}</Button>
          </form>
          <p v-if="!inventory.teams.length" class="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">{{ru?'Команд пока нет. Создайте первую команду.':'No teams yet. Create your first team.'}}</p>
          <div v-else class="grid gap-3 sm:grid-cols-2">
            <button v-for="item in inventory.teams" :key="item.id" class="rounded-xl border p-4 text-left transition-colors hover:bg-muted/40" :class="selectedTeam===item.id?'border-primary bg-primary/5':'border-border'" @click="selectedTeam=item.id;selectedUser=''">
              <div class="flex items-center justify-between gap-2"><span class="font-medium" :title="item.id">{{item.name}}</span><Badge variant="secondary">{{item.member_ids.length}}</Badge></div>
              <p class="mt-2 text-xs text-muted-foreground">{{ru?'Владелец':'Owner'}}: {{person(item.owner_user_id)}}</p>
            </button>
          </div>
          <div v-if="team" class="space-y-4 rounded-xl border border-border p-4">
            <div class="flex items-center justify-between gap-3"><h3 class="font-semibold">{{team.name}}</h3><Button variant="ghost" size="sm" :disabled="blocked" @click="edit('team',team)"><Pencil class="mr-2 size-4"/>{{ru?'Переименовать':'Rename'}}</Button></div>
            <form class="flex flex-wrap gap-3" @submit.prevent="send('team.member.add',{id:team.id,user_id:selectedUser})">
              <select v-model="selectedUser" :aria-label="ru?'Пользователь для добавления':'User to add'" :class="inputClass" class="min-w-56 flex-1" :disabled="blocked"><option value="">{{ru?'Выберите пользователя':'Select a user'}}</option><option v-for="user in candidates" :key="user.id" :value="user.id">{{user.name||user.email}}</option></select>
              <Button type="submit" :disabled="blocked||!selectedUser"><Plus class="mr-2 size-4"/>{{ru?'Добавить участника':'Add member'}}</Button>
            </form>
            <p v-if="!candidates.length" class="text-xs text-muted-foreground">{{ru?'Все доступные пользователи уже в команде. Другую учётную запись можно подключить в разделе «Пользователи».':'All available users are members. Connect another account in Users.'}}</p>
            <div v-for="id in team.member_ids" :key="id" class="flex items-center justify-between gap-2 border-t border-border pt-3">
              <span class="text-sm">{{person(id)}} <Badge v-if="id===team.owner_user_id" class="ml-2" variant="outline">{{ru?'Владелец':'Owner'}}</Badge></span>
              <Button v-if="id!==team.owner_user_id" variant="ghost" size="sm" :disabled="blocked" @click="send('team.member.remove',{id:team.id,user_id:id})"><X class="mr-2 size-4"/>{{ru?'Убрать из команды':'Remove member'}}</Button>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card v-if="view==='projects'">
        <CardHeader><CardTitle>{{ru?'Проекты':'Projects'}}</CardTitle></CardHeader>
        <CardContent class="space-y-5">
          <form class="flex flex-wrap items-end gap-3" @submit.prevent="send('project.create',{name:projectName.trim(),team_id:projectTeam||null})">
            <label class="min-w-48 flex-1 space-y-1 text-sm">{{ru?'Название проекта':'Project name'}}<Input v-model="projectName" required maxlength="255" :disabled="blocked" :placeholder="ru?'Например, Основной продукт':'For example, Main product'"/></label>
            <label class="space-y-1 text-sm">{{ru?'Владелец проекта':'Project owner'}}<select v-model="projectTeam" :class="inputClass" class="block w-full min-w-48" :disabled="blocked"><option value="">{{ru?'Мой личный проект':'My personal project'}}</option><option v-for="item in inventory.teams" :key="item.id" :value="item.id">{{item.name}}</option></select></label>
            <Button type="submit" :disabled="blocked||!projectName.trim()"><Plus class="mr-2 size-4"/>{{ru?'Создать проект':'Create project'}}</Button>
          </form>
          <div class="divide-y divide-border">
            <div v-for="project in inventory.projects" :key="project.id" class="flex flex-wrap items-center justify-between gap-3 py-4"><div><p class="font-medium" :title="project.id">{{project.name}}</p><p class="mt-1 text-sm text-muted-foreground">{{ru?'Владелец':'Owner'}}: {{owner(project)}}</p></div><Button variant="ghost" size="sm" :disabled="blocked" @click="edit('project',project)"><Pencil class="mr-2 size-4"/>{{ru?'Переименовать':'Rename'}}</Button></div>
          </div>
        </CardContent>
      </Card>
      <Card v-if="editing">
        <CardHeader><CardTitle>{{ru?'Изменить название':'Change name'}}</CardTitle></CardHeader>
        <CardContent><form class="flex flex-wrap gap-3" @submit.prevent="saveName"><Input v-model="editing.name" :aria-label="ru?'Новое название':'New name'" class="min-w-48 flex-1" required maxlength="255" :disabled="blocked"/><Button type="submit" :disabled="blocked||!editing.name.trim()">{{ru?'Сохранить':'Save'}}</Button><Button variant="outline" :disabled="busy" @click="editing=null">{{ru?'Отмена':'Cancel'}}</Button></form></CardContent>
      </Card>
    </template>
  </div>
</template>
