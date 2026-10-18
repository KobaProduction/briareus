<script setup lang="ts">
import {computed,ref,watch} from "vue"
import {useI18n} from "vue-i18n"
import {isPlatformProjectId} from "../api/platform-current"
import {Button} from "@/shared/ui/button"
import {Input} from "@/shared/ui/input"
const props=defineProps<{focusedProjectId:string|null;busy:boolean}>()
const emit=defineEmits<{select:[id:string|null]}>()
const {locale}=useI18n()
const value=ref(props.focusedProjectId??"")
watch(()=>props.focusedProjectId,id=>{value.value=id??""})
const valid=computed(()=>isPlatformProjectId(value.value.trim()))
const labels=computed(()=>locale.value==="ru"?{
  label:"Открыть проект по ID",open:"Проверить и выбрать проект",back:"Вернуться к списку проектов",
  focused:"Адресный просмотр одного проекта. Это не полный список проектов и команд.",
  inventory:"Список ограничен сервером. Известный ID можно проверить отдельно; сам ID не даёт доступа.",
  invalid:"Требуется канонический UUIDv4 проекта",checking:"Проверяем проект…",
}:{
  label:"Open Project by ID",open:"Verify and select Project",back:"Return to Project list",
  focused:"Viewing one exact Project, not the complete Project and Team inventory.",
  inventory:"The server bounds this list. A known ID can be checked separately; the ID itself grants no access.",
  invalid:"Enter a canonical Project UUIDv4",checking:"Checking Project…",
})
function submit():void{if(valid.value&&!props.busy)emit("select",value.value.trim())}
</script>
<template>
  <details class="mb-5 min-w-0 rounded-xl border border-border bg-muted/20 p-3">
    <summary class="cursor-pointer text-sm font-medium">{{labels.label}}</summary>
    <form class="space-y-3" @submit.prevent="submit">
      <label class="block pt-3 text-xs font-medium"><span>{{labels.label}}</span>
        <Input v-model="value" class="mt-2" maxlength="64" autocomplete="off" :disabled="busy"/>
      </label>
      <p class="text-xs leading-5 text-muted-foreground">{{focusedProjectId?labels.focused:labels.inventory}}</p>
      <p v-if="value&&!valid" role="status" class="text-xs text-muted-foreground">{{labels.invalid}}</p>
      <div class="flex flex-wrap gap-2">
        <Button type="submit" variant="outline" size="sm" :disabled="busy||!valid">{{busy?labels.checking:labels.open}}</Button>
        <Button v-if="focusedProjectId" type="button" variant="ghost" size="sm" @click="emit('select',null)">{{labels.back}}</Button>
      </div>
    </form>
  </details>
</template>
