<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue"
import { Modal } from "ant-design-vue"
import { ArrowUp, FolderPlus, RefreshCw, Upload } from "lucide-vue-next"
import { useI18n } from "vue-i18n"
import { managementApi, type FilesState } from "@/shared/api/management"
import { formatBytes } from "@/shared/lib/format"
import { notifications } from "@/shared/notifications/bus"
import AppDialog from "@/shared/ui/AppDialog.vue"
import { canPreviewTextFile, readTextPreview } from "./model/text-preview"
import Button from "@/shared/ui/Button.vue"
import DataTable from "@/shared/ui/DataTable.vue"
import PageHeader from "@/shared/ui/PageHeader.vue"

const {t}=useI18n()
const state=ref<FilesState|null>(null),loading=ref(false),error=ref(""),uploadOpen=ref(false),mkdirOpen=ref(false),mkdirName=ref(""),uploadFile=ref<File|null>(null),overwrite=ref(false)
const rows=computed(()=>state.value?.listing.entries??[])
const previewOpen=ref(false),previewLoading=ref(false),previewName=ref(""),previewText=ref(""),previewError=ref("")
let previewController:AbortController|null=null
function closePreview(){previewController?.abort();previewController=null;previewOpen.value=false}
async function preview(record:Record<string,unknown>){
  if(!canPreviewTextFile(record))return
  closePreview()
  const controller=new AbortController()
  previewController=controller
  previewName.value=String(record.name)
  previewText.value=""
  previewError.value=""
  previewLoading.value=true
  previewOpen.value=true
  try{
    previewText.value=await readTextPreview(managementApi.fileDownloadUrl(String(record.path)),controller.signal)
  }catch(e){
    if(!controller.signal.aborted)previewError.value=e instanceof Error?e.message:String(t("files.previewFailed"))
  }finally{
    if(previewController===controller){previewLoading.value=false;previewController=null}
  }
}
async function copyPreview(){
  try{
    await navigator.clipboard.writeText(previewText.value)
    notifications.success(String(t("jsonView.copied")))
  }catch{notifications.error(String(t("files.previewCopyFailed")))}
}
const columns=[{title:t('files.name'),dataIndex:'name',key:'name'},{title:t('files.type'),dataIndex:'type',key:'type',width:110},{title:t('files.size'),dataIndex:'size_bytes',key:'size_bytes',width:120},{title:t('common.actions'),key:'actions',width:270}]
async function load(path=state.value?.current_path??'',append=false){if(loading.value)return;loading.value=true;error.value='';try{const offset=append?rows.value.length:0;const next=await managementApi.files(path,offset,200);if(append&&state.value&&state.value.current_path===next.current_path){state.value={...next,listing:{...next.listing,entries:[...state.value.listing.entries,...next.listing.entries]}}}else state.value=next}catch(e){error.value=e instanceof Error?e.message:'Unable to load files'}finally{loading.value=false}}
async function loadMore(){if(state.value?.listing.truncated)await load(state.value.current_path,true)}
function selectUpload(event:Event){const input=event.target as HTMLInputElement;uploadFile.value=input.files?.[0]??null}
async function upload(){if(!uploadFile.value)return;await managementApi.uploadFile(state.value?.current_path??'',uploadFile.value,overwrite.value);uploadOpen.value=false;uploadFile.value=null;notifications.success(String(t('notifications.saved')));await load()}
async function mkdir(){if(!mkdirName.value.trim())return;await managementApi.mkdir(state.value?.current_path??'',mkdirName.value);mkdirOpen.value=false;mkdirName.value='';notifications.success(String(t('notifications.saved')));await load()}
async function remove(record:Record<string,unknown>){const path=String(record.path??'');if(!window.confirm(`Delete ${path}?`))return;await managementApi.deleteFile(path,record.type==='directory');notifications.success(String(t('notifications.deleted')),path);await load()}
onMounted(()=>load(''))
onUnmounted(closePreview)
</script>
<template><div class="space-y-6"><PageHeader :title="t('nav.files')" :description="`${t('files.workspace')} /${state?.current_path||''}`"><Button v-if="state?.current_path" variant="outline" size="sm" @click="load(state.parent_path)"><ArrowUp class="mr-2 size-4"/>{{t('files.up')}}</Button><Button variant="outline" size="sm" @click="load()"><RefreshCw class="mr-2 size-4"/>{{t('common.refresh')}}</Button><Button variant="outline" size="sm" @click="mkdirOpen=true"><FolderPlus class="mr-2 size-4"/>{{t('files.newFolder')}}</Button><Button size="sm" @click="uploadOpen=true"><Upload class="mr-2 size-4"/>{{t('files.upload')}}</Button></PageHeader><div v-if="state" class="flex flex-wrap gap-5 text-xs text-muted-foreground"><span>{{state.listing.total}} {{t('files.entries')}}</span><span>{{formatBytes(state.stats.size_bytes)}} {{t('files.stored')}}</span><span>{{formatBytes(state.stats.free_bytes)}} {{t('files.free')}}</span></div><p v-if="error" class="text-sm text-destructive">{{error}}</p><DataTable :columns="columns" :data-source="rows" :loading="loading" row-key="path" :pagination="false" virtual :scroll-y="600" @end-reached="loadMore"><template #bodyCell="{column,record,value}"><template v-if="column.key==='name'"><button v-if="record.type==='directory'" class="font-medium underline underline-offset-4" @click="load(record.path)">{{record.name}}/</button><span v-else>{{record.name}}</span></template><template v-else-if="column.key==='size_bytes'">{{record.type==='file'?formatBytes(record.size_bytes):'—'}}</template><template v-else-if="column.key==='actions'"><div class="flex items-center gap-2"><Button v-if="canPreviewTextFile(record)" variant="ghost" size="sm" @click="preview(record)">{{t('files.preview')}}</Button><a v-if="record.type==='file'" class="btn-link" :href="managementApi.fileDownloadUrl(record.path)">{{t('files.download')}}</a><Button variant="ghost" size="sm" @click="remove(record)">{{t('common.delete')}}</Button></div></template><template v-else><span class="truncate">{{value ?? '—'}}</span></template></template></DataTable><AppDialog :open="previewOpen" :title="previewName" width="880px" :close-label="String(t('common.close'))" @close="closePreview"><div class="space-y-3"><div class="flex justify-end"><Button v-if="!previewLoading && !previewError" variant="outline" size="sm" @click="copyPreview">{{t('jsonView.copy')}}</Button></div><p v-if="previewLoading" class="text-sm text-muted-foreground">{{t('common.loading')}}</p><p v-else-if="previewError" class="text-sm text-destructive">{{t('files.previewFailed')}}: {{previewError}}</p><pre v-else class="max-h-[65vh] overflow-auto rounded-lg border border-border bg-muted/30 p-4 text-xs leading-relaxed whitespace-pre-wrap break-words">{{previewText}}</pre></div></AppDialog><Modal v-model:open="uploadOpen" :title="t('files.uploadTitle')" @ok="upload"><div class="space-y-3 py-3"><input type="file" @change="selectUpload"/><label class="flex items-center gap-2 text-sm"><input v-model="overwrite" type="checkbox"/>{{t('files.overwrite')}}</label></div></Modal><Modal v-model:open="mkdirOpen" :title="t('files.createFolder')" @ok="mkdir"><label class="block space-y-2 py-3 text-sm"><span>{{t('files.name')}}</span><input v-model="mkdirName" class="field" @keyup.enter="mkdir"/></label></Modal></div></template>
