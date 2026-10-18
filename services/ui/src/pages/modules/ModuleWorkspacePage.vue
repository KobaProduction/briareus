<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue"
import { ArrowRight, ChevronRight, Monitor, Settings2, WifiOff } from "lucide-vue-next"
import { useUiPreferences } from "@/shared/lib/preferences"
import { setLocale } from "@/shared/i18n"
import { ModuleOperationsPanel } from "@/widgets/mcp-modules"
import { moduleById, modules, moduleLocationHash, parseModuleLocation } from "@/features/modules"
import type { ModuleId, ModuleSetting, ModuleView } from "@/features/modules/types"
import type { VerifiedPlatformContext } from "@/features/platform/api/platform-current"
import type { RauthyPanelIdentity } from "@/features/platform/api/rauthy-oidc"
import { FilesAccessPanel } from "@/widgets/files-access"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/shared/ui/tabs"
import { Card, CardContent } from "@/shared/ui/card"
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/shared/ui/select"
import { Switch } from "@/shared/ui/switch"

const props=withDefaults(defineProps<{
  initial?:ModuleId
  /** Presentation-only: actual session and Files effects are authorized by BFF/Hand. */
  filesProjectCanRequest?:boolean
  filesContext?:VerifiedPlatformContext|null
  filesIdentity?:RauthyPanelIdentity|null
  filesProjectId?:string|null
}>(),{initial:"web",filesProjectCanRequest:false})
const emit=defineEmits<{openSessions:[]}>()
const prefs=useUiPreferences()
const lang=computed(() => prefs.locale.value)
const selected=ref<ModuleId>(props.initial)
const view=ref<ModuleView>("overview")
const module=computed(()=>moduleById(selected.value) ?? modules[0]!)
const values=ref<Record<string,string|boolean>>({})
const touched=ref(false)
function applyHash():void {
  const location=parseModuleLocation(window.location.hash,props.initial)
  selected.value=location.module
  view.value=location.view
}
function navigateModule(id:ModuleId, pane:ModuleView):void {
  selected.value=id
  view.value=pane
  const next=moduleLocationHash(id,pane)
  if(window.location.hash!==next)window.location.hash=next
}
function selectModule(id:ModuleId):void { navigateModule(id,"overview");filter.value="" }
function selectView(pane:ModuleView):void { navigateModule(selected.value,pane) }
function selectTab(value:string|number):void {
  if(value==="overview"||value==="settings"||value==="global")selectView(value)
}
onMounted(()=>{
  applyHash()
  window.addEventListener("hashchange",applyHash)
})
onBeforeUnmount(()=>window.removeEventListener("hashchange",applyHash))
watch([selected,view],()=>{values.value={};touched.value=false})
const words=computed(()=>lang.value==="ru"?{
  title:"Модули MCP",overview:"Операции",settings:"Настройки модуля",general:"Общие настройки",globalHint:"Язык, тема, плотность и часовой пояс относятся ко всему Briareus",moduleHint:"Параметры отдельного модуля не влияют на остальные сервисы",backend:"Подключение Control Panel API",unavailable:"Серверный контракт модуля не подключён. Данные, WebSocket и операции недоступны.",noData:"Нет подтверждённых серверных записей",capabilities:"Возможности",configure:"Параметры сервера",pending:"Изменения не отправлены. Применение доступно только после подтверждённого API-контракта и прав пользователя.",save:"Применить настройки",unsupported:"Недоступно до подключения Control Panel API",connection:"Состояние подключения",offline:"Не подключено",tabs:"Вкладки и сеансы",emptyTabs:"Нет полученных вкладок браузера",actions:"Операции",files:"Путь / Тип / Размер / Действия",jobs:"Рабочее пространство / Задание / Состояние",git:"Аккаунт / Репозиторий / Ветка",scope:"Область доступа",source:"Источник данных: Control Panel API",external:"Внешние учётные данные и секреты не сохраняются в браузере",choose:"Выберите значение",inspect:"Обзор",gitRecords:"Нет подтверждённых аккаунтов и репозиториев",close:"Закрыть",denied:"Контролы изменяют только черновик формы, серверные значения не меняются",filter:"Поиск среди модулей",moduleType:"MCP / служебный модуль"
}: {
  title:"MCP modules",overview:"Operations",settings:"Module settings",general:"Global settings",globalHint:"Language, theme, density and time zone apply across Briareus",moduleHint:"Module-specific settings do not alter other services",backend:"Control Panel API connection",unavailable:"The module's server contract is not connected. Data, WebSocket and actions are unavailable.",noData:"No verified server records",capabilities:"Capabilities",configure:"Server-owned parameters",pending:"Changes have not been sent. Applying settings requires an accepted API contract and verified user permissions.",save:"Apply settings",unsupported:"Unavailable until Control Panel API is connected",connection:"Connection status",offline:"Not connected",tabs:"Tabs and sessions",emptyTabs:"No browser tabs received",actions:"Operations",files:"Path / Type / Size / Actions",jobs:"Workspace / Job / Status",git:"Account / Repository / Branch",scope:"Access scope",source:"Data source: Control Panel API",external:"External credentials and secrets are not stored in the browser",choose:"Choose a value",inspect:"Overview",gitRecords:"No verified accounts or repositories",close:"Close",denied:"Controls only edit the form draft, not server values",filter:"Search modules",moduleType:"MCP / service module"
})
const filter=ref("")
const visible=computed(()=>modules.filter(m=>`${m.title.en} ${m.title.ru} ${m.summary.en} ${m.summary.ru}`.toLocaleLowerCase().includes(filter.value.toLocaleLowerCase().trim())))
function setSetting(field:ModuleSetting,value:string|number|boolean):void {
  if(field.kind==="toggle"){
    if(typeof value!=="boolean")return
  }else if(typeof value!=="string" && typeof value!=="number")return
  values.value={...values.value,[field.key]:typeof value==="number"?String(value):value}
  touched.value=true
}
function selectedSetting(field:ModuleSetting):string|boolean {
  return values.value[field.key]??(field.kind==="toggle"?false:"")
}
function setUiLocale(value:unknown):void{
  if(value==="en"||value==="ru")setLocale(value)
}
function setUiTheme(value:unknown):void{
  if(value==="dark"||value==="light"||value==="system")prefs.theme.value=value
}
function setUiDensity(value:unknown):void{
  if(value==="comfortable"||value==="compact")prefs.density.value=value
}
function setUiTimeZone(value:unknown):void{
  if(value==="UTC"||value==="system")prefs.displayTimeZone.value=value
}
</script>
<template>
  <section class="mx-auto w-full max-w-[1440px] space-y-5 rounded-[22px] border border-border bg-card p-3 shadow-sm sm:p-6" :aria-label="words.title">
    <header class="flex flex-wrap items-start justify-between gap-3 border-b border-border pb-4">
      <div class="flex min-w-0 flex-wrap items-center gap-3">
        <div class="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary"><Monitor class="size-5" aria-hidden="true" /></div>
        <div class="min-w-0"><h2 class="text-lg font-semibold text-foreground">{{words.title}}</h2><p class="text-xs text-muted-foreground">{{words.source}}</p></div>
      </div>

    </header>

    <div class="grid min-w-0 gap-5">
      <nav class="min-w-0 space-y-2" :aria-label="words.title">
        <label class="block max-w-sm text-xs font-semibold text-muted-foreground">{{words.filter}}<Input v-model="filter" type="search" class="mt-2" maxlength="100" :placeholder="words.filter" /></label>
        <div class="grid grid-cols-2 gap-1 sm:grid-cols-3 lg:grid-cols-4" :class="filter.trim()?'':'lg:hidden'">
          <Button v-for="item in visible" :key="item.id" type="button" size="sm"
            class="min-h-11 min-w-0 justify-between gap-2 text-left"
            :variant="item.id===selected?'secondary':'ghost'"
            :aria-current="item.id===selected?'page':undefined" @click="selectModule(item.id)">
            <span class="truncate">{{item.title[lang]}}</span><ChevronRight class="size-3.5 shrink-0 opacity-60" aria-hidden="true"/>
          </Button>
        </div>
        <p v-if="visible.length===0 && filter.trim()" class="p-2 text-xs text-muted-foreground">{{words.noData}}</p>
      </nav>
      <article class="min-w-0 space-y-5">
        <div class="flex min-w-0 flex-wrap items-start justify-between gap-2">
          <div class="min-w-0"><p class="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{{words.moduleType}}</p><h3 class="mt-1 break-words text-xl font-semibold text-foreground">{{module.title[lang]}}</h3><p class="mt-2 max-w-2xl text-sm text-muted-foreground">{{module.summary[lang]}}</p></div>
          <span class="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/30 px-3 py-1 text-xs text-muted-foreground"><WifiOff class="size-3.5" aria-hidden="true"/>{{words.offline}}</span>
        </div>
        <Tabs :model-value="view" class="space-y-4" @update:model-value="selectTab">
          <TabsList class="flex h-auto min-h-11 w-full flex-nowrap justify-start gap-1 overflow-x-auto p-1 sm:w-fit" :aria-label="module.title[lang]">
            <TabsTrigger value="overview" class="min-h-9 shrink-0 whitespace-nowrap">{{words.overview}}</TabsTrigger>
            <TabsTrigger value="settings" class="min-h-9 shrink-0 whitespace-nowrap"><Settings2 class="mr-1 size-4" aria-hidden="true"/>{{words.settings}}</TabsTrigger>
            <TabsTrigger value="global" class="min-h-9 shrink-0 whitespace-nowrap">{{words.general}}</TabsTrigger>
          </TabsList>
        <TabsContent value="overview" class="space-y-5">
          <Card class="rounded-xl">
            <CardContent class="space-y-3 p-4 sm:p-5">
            <h4 class="text-sm font-semibold">{{words.capabilities}}</h4>
            <div class="grid gap-2 sm:grid-cols-2">
              <div v-for="(capability,i) in module.features" :key="i" class="flex gap-2 rounded-xl border border-border bg-muted/20 p-3 text-sm text-foreground"><span class="mt-1 size-1.5 shrink-0 rounded-full bg-primary" aria-hidden="true"/><span>{{capability[lang]}}</span></div>
            </div>
            </CardContent>
          </Card>
          <Card v-if="selected==='files'" class="min-w-0">
            <CardContent class="flex flex-wrap items-center justify-between gap-3 py-4">
              <p class="max-w-xl text-sm text-muted-foreground">{{lang==='ru'
                ?'Для работы с Files нужна подтверждённая AgentSession и проверка Cedar на стороне Hand. Файловые операции пока закрыты.'
                :'Files requires a verified AgentSession and a Cedar decision by the Hand. File operations remain disabled.'}}</p>
              <Button type="button" variant="outline" :disabled="!filesProjectCanRequest" @click="emit('openSessions')">
                {{lang==='ru'?'Перейти к AgentSessions':'Open AgentSessions'}} <ArrowRight class="ml-2 size-4" aria-hidden="true"/>
              </Button>
            </CardContent>
          </Card>
          <FilesAccessPanel v-if="selected==='files'&&filesContext&&filesIdentity&&filesProjectId"
            :key="filesProjectId" :identity="filesIdentity" :context="filesContext" :project-id="filesProjectId"
            />
          <ModuleOperationsPanel :module="selected" />
          <section class="settings-card space-y-3">
            <h4 class="text-sm font-semibold">{{words.connection}}</h4>
            <p class="text-sm text-muted-foreground" role="status">{{words.unavailable}}</p>
          </section>
        </TabsContent>
        <TabsContent value="settings" class="space-y-4">
          <div class="rounded-xl border border-border bg-muted/30 p-4"><h4 class="font-semibold">{{words.settings}}</h4><p class="mt-1 text-sm text-muted-foreground">{{words.moduleHint}}. {{words.external}}</p></div>
          <form class="settings-card space-y-4" @submit.prevent>
            <fieldset class="space-y-4"><legend class="mb-2 text-sm font-semibold">{{words.configure}}</legend>
              <label v-for="field in module.settings" :key="field.key" class="block space-y-1.5 text-sm"><span class="font-semibold">{{field.label[lang]}}</span><span class="block text-xs text-muted-foreground">{{field.description[lang]}}</span>
                <Select v-if="field.kind==='select'" :model-value="String(selectedSetting(field))"
                  @update:model-value="value=>setSetting(field,String(value))">
                  <SelectTrigger class="min-h-10" :aria-label="field.label[lang]">
                    <SelectValue :placeholder="words.choose"/>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="option in field.options" :key="option" :value="option">{{option}}</SelectItem>
                  </SelectContent>
                </Select>
                <Switch v-else-if="field.kind==='toggle'" :model-value="Boolean(selectedSetting(field))"
                  :aria-label="field.label[lang]" @update:model-value="enabled=>setSetting(field,enabled)" />
                <Input v-else :model-value="String(selectedSetting(field))" class="min-h-10"
                  :type="field.kind==='number'?'number':'text'"
                  :min="field.kind==='number'?1:undefined"
                  :maxlength="field.kind==='text'?160:undefined"
                  autocomplete="off" :aria-label="field.label[lang]"
                  @update:model-value="value=>setSetting(field,value)" />
              </label>
            </fieldset>
            <div class="space-y-2 border-t border-border pt-4"><p role="status" class="text-xs text-muted-foreground">{{touched?words.pending:words.denied}}</p><Button type="button" size="sm" disabled :title="words.unsupported">{{words.save}}</Button></div>
          </form>
        </TabsContent>
        <TabsContent value="global" class="space-y-5">
          <div class="settings-card space-y-4">
            <h4 class="text-base font-semibold">{{words.general}}</h4>
            <p class="text-sm text-muted-foreground">{{words.globalHint}}</p>
            <div class="max-w-sm space-y-2 text-sm">
              <p class="font-semibold">{{lang==='ru'?'Язык интерфейса':'Interface language'}}</p>
              <Select :model-value="prefs.locale.value" @update:model-value="setUiLocale">
                <SelectTrigger class="min-h-10" :aria-label="lang==='ru'?'Язык интерфейса':'Interface language'">
                  <SelectValue/>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ru">Русский</SelectItem>
                  <SelectItem value="en">English</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="max-w-sm space-y-2 text-sm">
              <p class="font-semibold">{{lang==='ru'?'Тема':'Theme'}}</p>
              <Select :model-value="prefs.theme.value" @update:model-value="setUiTheme">
                <SelectTrigger class="min-h-10" :aria-label="lang==='ru'?'Тема':'Theme'"><SelectValue/></SelectTrigger>
                <SelectContent>
                  <SelectItem value="system">{{lang==='ru'?'Авто':'Auto'}}</SelectItem>
                  <SelectItem value="light">{{lang==='ru'?'Светлая':'Light'}}</SelectItem>
                  <SelectItem value="dark">{{lang==='ru'?'Тёмная':'Dark'}}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="max-w-sm space-y-2 text-sm">
              <p class="font-semibold">{{lang==='ru'?'Плотность':'Density'}}</p>
              <Select :model-value="prefs.density.value" @update:model-value="setUiDensity">
                <SelectTrigger class="min-h-10" :aria-label="lang==='ru'?'Плотность':'Density'"><SelectValue/></SelectTrigger>
                <SelectContent>
                  <SelectItem value="compact">{{lang==='ru'?'Компактно':'Compact'}}</SelectItem>
                  <SelectItem value="comfortable">{{lang==='ru'?'Комфортно':'Comfortable'}}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="max-w-sm space-y-2 text-sm">
              <p class="font-semibold">{{lang==='ru'?'Часовой пояс отображения':'Display time zone'}}</p>
              <Select :model-value="prefs.displayTimeZone.value" @update:model-value="setUiTimeZone">
                <SelectTrigger class="min-h-10" :aria-label="lang==='ru'?'Часовой пояс отображения':'Display time zone'"><SelectValue/></SelectTrigger>
                <SelectContent>
                  <SelectItem value="system">{{lang==='ru'?'Устройство':'Device'}}</SelectItem>
                  <SelectItem value="UTC">UTC</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </TabsContent>
        </Tabs>
      </article>
    </div>
  </section>
</template>
