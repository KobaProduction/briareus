<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { Eye, EyeOff } from "lucide-vue-next"
import {submitNativePasswordLogin,type NativeLoginOutcome} from "@/features/platform/api/native-first-factor"
import {cancelNativePrelogin} from "@/features/platform/api/native-prelogin-control"
import {
  readRauthyPanelState,
  signOutRauthyPanel,
  type RauthyPanelState,
  type RauthyPanelIdentity,
} from "@/features/platform/api/rauthy-oidc"

type LoginViewState=RauthyPanelState | {kind:"checking"}
const props=defineProps<{
  /** Already checked by the authoritative OIDC panel; do not poll it again. */
  initialState?:RauthyPanelState|null
  /** Parent orchestrates logout and cancels its pending membership read. */
  managedLogout?:boolean
}>()
const emit=defineEmits<{
  logoutRequested:[]
  identity:[value:RauthyPanelIdentity|null]
  state:[value:LoginViewState]
}>()
const { locale } = useI18n()

const state = ref<RauthyPanelState | { kind: "checking" }>({ kind: "checking" })
const busy = ref(false)
const error = ref(false)
const logoutFailure = ref<"forbidden" | "unavailable" | "uncertain" | null>(null)
const hadSession = ref(false)
const ended = ref(false)
const email=ref("")
const password=ref("")
const passwordVisible=ref(false)
const loginBusy=ref(false)
const cancellingLogin=ref(false)
const loginMessage=ref<"invalid"|"provider"|"mfa"|"rate_limited"|"expired"|"unavailable"|"unconfirmed"|"cancelled"|null>(null)
let loginController:AbortController|null=null
let lastCheckedAt = 0
let expiryTimer: ReturnType<typeof setTimeout> | null = null
let controller: AbortController | null = null

function acceptState(next:LoginViewState):void {
  state.value=next
  emit("state",next)
  if(next.kind==="signed_in"){
    emit("identity",next.identity)
    password.value=""
    passwordVisible.value=false
    hadSession.value=true
    ended.value=false
    if(expiryTimer!==null)clearTimeout(expiryTimer)
    // OidcPanelPage already owns freshness/visibility checks whenever
    // it supplies a verified browser snapshot. Do not independently poll
    // the same session a second time from the child login component.
    if(!props.initialState){
      const remaining=Date.parse(next.identity.expires_at)-Date.now()
      expiryTimer=setTimeout(()=>{void refresh()},Math.max(1000,Math.min(remaining,900000)))
    }
  }else{
    emit("identity",null)
    if(expiryTimer!==null){clearTimeout(expiryTimer);expiryTimer=null}
    if(next.kind==="signed_out"&&hadSession.value){
      ended.value=true
      hadSession.value=false
    }
  }
}
const labels = computed(() => locale.value === "ru" ? {
  title: "Вход в Control Panel",
  checking: "Проверяем сеанс…",
  unavailable: "Не удалось проверить сеанс.",
  ready: "Введите почту и пароль, чтобы войти.",
  signedIn: "Сеанс подтверждён.",
  scope: "Проверяем доступ к проектам.",
  logout: "Выйти",
  logoutError: "Выход не подтверждён. Проверьте сеанс ещё раз.",
  forbidden: "Доступ не подтверждён.",
  ended: "Сеанс завершён.",
  revokedFailure: "Не удалось подтвердить выход.",
  refresh: "Повторить проверку",
  checkResult: "Проверить результат входа",
  showPassword: "Показать пароль",
  hidePassword: "Скрыть пароль",
  email: "Электронная почта",
  password: "Пароль",
  signIn: "Войти",
  signingIn: "Проверяем данные…",
  cancelLogin: "Отменить вход",
  loginInvalid: "Не удалось войти. Проверьте адрес почты и пароль.",
  loginProvider: "Не удалось подтвердить вход. Повторите попытку; если ошибка сохраняется, обратитесь к администратору.",
  loginMfa: "Для аккаунта требуется дополнительная проверка. Этот способ входа пока не поддерживается.",
  loginRate: "Слишком много попыток. Повторите вход позже.",
  loginExpired: "Время проверки истекло. Попробуйте войти ещё раз.",
  loginUnavailable: "Не удалось выполнить вход. Проверьте подключение и повторите попытку.",
  loginUnconfirmed: "Результат входа не подтверждён. Проверьте сеанс перед новой попыткой.",
  loginCancelled: "Попытка входа остановлена.",
} : {
  title: "Control Panel sign-in",
  checking: "Checking session…",
  unavailable: "Unable to verify the session.",
  ready: "Enter your email and password to sign in.",
  signedIn: "Session verified.",
  scope: "Checking Project access.",
  logout: "Sign out",
  logoutError: "Sign-out was not confirmed. Check your session again.",
  forbidden: "Access was not verified.",
  ended: "Session ended.",
  revokedFailure: "Unable to confirm sign-out.",
  refresh: "Retry session check",
  checkResult: "Check sign-in result",
  showPassword: "Show password",
  hidePassword: "Hide password",
  email: "Email",
  password: "Password",
  signIn: "Sign in",
  signingIn: "Verifying credentials…",
  cancelLogin: "Cancel sign-in",
  loginInvalid: "Unable to sign in. Check your email and password.",
  loginProvider: "Sign-in could not be verified. Try again; if the problem persists, contact your administrator.",
  loginMfa: "Your account requires an additional verification step that is not yet supported.",
  loginRate: "Too many attempts. Try again later.",
  loginExpired: "Sign-in verification expired. Try signing in again.",
  loginUnavailable: "Unable to sign in. Check your connection and try again.",
  loginUnconfirmed: "Sign-in result is unconfirmed. Check your session before trying again.",
  loginCancelled: "Sign-in attempt cancelled.",
})

async function submitLogin():Promise<void>{
  if(loginBusy.value||busy.value||state.value.kind!=="signed_out")return
  const userEmail=email.value
  const userPassword=password.value
  // Preserve the input on a rejected/unavailable attempt: the user may
  // correct a typo or retry without retyping an otherwise valid password.
  // It stays only in this component's memory, never in storage or logs.
  loginMessage.value=null
  const request=new AbortController()
  loginController?.abort()
  loginController=request
  loginBusy.value=true
  const deadline=setTimeout(()=>request.abort(),65000)
  try{
    const outcome:NativeLoginOutcome=await submitNativePasswordLogin(userEmail,userPassword,request.signal)
    if(loginController!==request)return
    if(outcome.kind==="session_issued"||outcome.kind==="uncertain"){
      // A 200 from the native first factor is *not* proof of a signed User.
      // Verify the opaque HttpOnly session independently; the parent will
      // still require current Project membership from its owner BFF.
      const read=await readRauthyPanelState(request.signal)
      if(loginController!==request)return
      if(read.kind==="signed_in"){
        acceptState(read)
        loginMessage.value=null
        return
      }
      loginMessage.value="unconfirmed"
      return
    }
    loginMessage.value=outcome.kind==="continuation_unavailable"?"mfa":
      outcome.kind==="rate_limited"?"rate_limited":
      outcome.kind==="expired"?"expired":
      outcome.kind==="provider_rejected"?"provider":
      outcome.kind==="rejected"?"invalid":
      outcome.kind==="cancelled"?"cancelled":"unavailable"
  }catch{
    if(loginController===request)loginMessage.value="unconfirmed"
  }finally{
    clearTimeout(deadline)
    if(loginController===request){loginController=null;loginBusy.value=false}
  }
}
async function cancelLogin():Promise<void>{
  if(!loginBusy.value||cancellingLogin.value)return
  cancellingLogin.value=true
  loginController?.abort()
  loginController=null
  password.value=""
  passwordVisible.value=false
  const request=new AbortController()
  const deadline=setTimeout(()=>request.abort(),8000)
  try{
    // Keep the form locked until Backend confirms cancellation; otherwise a
    // late cancel could revoke a new cookie-bound attempt.
    const result=await cancelNativePrelogin(request.signal)
    loginMessage.value=result.kind==="cancelled"?"cancelled":"unconfirmed"
  }finally{
    clearTimeout(deadline)
    loginBusy.value=false
    cancellingLogin.value=false
  }
}
const loginStatus=computed(()=>loginMessage.value==="invalid"?labels.value.loginInvalid:
  loginMessage.value==="provider"?labels.value.loginProvider:
  loginMessage.value==="mfa"?labels.value.loginMfa:
  loginMessage.value==="rate_limited"?labels.value.loginRate:
  loginMessage.value==="expired"?labels.value.loginExpired:
  loginMessage.value==="unavailable"?labels.value.loginUnavailable:
  loginMessage.value==="unconfirmed"?labels.value.loginUnconfirmed:
  loginMessage.value==="cancelled"?labels.value.loginCancelled:"")

async function refresh(): Promise<void> {
  if(busy.value)return
  lastCheckedAt=Date.now()
  controller?.abort()
  if(expiryTimer!==null){clearTimeout(expiryTimer);expiryTimer=null}
  const request = new AbortController()
  controller = request
  acceptState({kind:"checking"})
  error.value = false
  logoutFailure.value=null
  const deadline = setTimeout(() => request.abort(), 8000)
  try {
    const result = await readRauthyPanelState(request.signal)
    if (controller === request) {
      acceptState(request.signal.aborted
        ? {kind:"unavailable",reason:"network"} : result)
    }
  } finally {
    clearTimeout(deadline)
    if (controller === request) controller = null
  }
}

async function logout(): Promise<void> {
  if (busy.value) return
  if(props.managedLogout){emit("logoutRequested");return}
  busy.value = true
  error.value = false
  controller?.abort()
  const request = new AbortController()
  controller = request
  const deadline = setTimeout(() => request.abort(), 8000)
  try {
    const outcome = await signOutRauthyPanel(request.signal)
    if (controller === request) {
      if (!request.signal.aborted && outcome.kind === "revoked"){
        acceptState({kind:"signed_out"})
        hadSession.value=false
        ended.value=false
      }else {
        error.value=true
        logoutFailure.value=outcome.kind==="revoked"?"uncertain":outcome.kind
        acceptState({kind:"unavailable",reason:"session_unavailable"})
      }
    }
  } finally {
    clearTimeout(deadline)
    if (controller === request) controller = null
    busy.value = false
  }
}

function onVisibility():void {
  if(props.initialState||busy.value)return
  if(document.visibilityState==="visible"&&Date.now()-lastCheckedAt>10000)void refresh()
}
onMounted(() => {
  if(props.initialState){
    lastCheckedAt=Date.now()
    acceptState(props.initialState)
  }else void refresh()
  document.addEventListener("visibilitychange",onVisibility)
})
watch(()=>props.initialState,next=>{
  if(!next)return
  // If the parent reconciles the authoritative provider session, reject
  // any older in-flight child request rather than overwrite newer evidence.
  controller?.abort()
  controller=null
  lastCheckedAt=Date.now()
  acceptState(next)
})
onBeforeUnmount(() => {
  emit("identity",null)
  controller?.abort(); controller=null
  loginController?.abort();loginController=null
  password.value=""
  passwordVisible.value=false
  if(expiryTimer!==null)clearTimeout(expiryTimer)
  document.removeEventListener("visibilitychange",onVisibility)
})
</script>

<template>
  <section class="rounded-2xl border border-border bg-card p-5 sm:p-7"
    aria-labelledby="rauthy-sign-in-title">
    <h1 id="rauthy-sign-in-title" class="text-xl font-semibold text-foreground">{{labels.title}}</h1>
    <p v-if="state.kind==='checking'" role="status" class="mt-4 text-sm text-muted-foreground">{{labels.checking}}</p>
    <div v-else-if="state.kind==='signed_in'" class="mt-4 space-y-4">
      <p role="status" class="text-sm font-medium">{{labels.signedIn}}</p>
      <p class="text-sm text-muted-foreground">{{labels.scope}}</p>
      <button type="button"
        class="min-h-11 w-full rounded-lg border border-border px-4 text-sm font-medium hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:opacity-50"
        :disabled="busy" @click="logout">{{labels.logout}}</button>
    </div>
    <div v-else class="mt-4 space-y-4">
      <p role="status" class="text-sm text-muted-foreground">
        {{state.kind==='unavailable'?(state.reason==='forbidden'?labels.forbidden:labels.unavailable):
          ended?labels.ended:labels.ready}}
      </p>
      <form v-if="state.kind==='signed_out'" class="space-y-4" autocomplete="on" @submit.prevent="submitLogin">
        <label class="block space-y-1 text-sm font-medium">
          <span>{{labels.email}}</span>
          <input v-model="email" name="username" type="email" autocomplete="username" required maxlength="320"
            :disabled="loginBusy" class="w-full rounded-lg border border-input bg-background px-3 py-2 text-foreground focus-visible:outline-2 focus-visible:outline-ring"/>
        </label>
        <div class="space-y-1 text-sm font-medium">
          <label for="briareus-login-password" class="block">{{labels.password}}</label>
          <div class="relative">
            <input id="briareus-login-password" v-model="password" name="password"
              :type="passwordVisible?'text':'password'"
              autocomplete="current-password" required maxlength="256"
              :disabled="loginBusy"
              class="w-full min-h-11 rounded-lg border border-input bg-background px-3 py-2 pr-12 text-foreground focus-visible:outline-2 focus-visible:outline-ring"/>
            <button type="button"
              class="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-lg text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
              :aria-label="passwordVisible?labels.hidePassword:labels.showPassword"
              :title="passwordVisible?labels.hidePassword:labels.showPassword"
              :aria-pressed="passwordVisible"
              @click="passwordVisible=!passwordVisible">
              <EyeOff v-if="passwordVisible" class="size-5" aria-hidden="true"/>
              <Eye v-else class="size-5" aria-hidden="true"/>
            </button>
          </div>
        </div>
        <button type="submit"
          class="min-h-11 w-full rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:opacity-50"
          :disabled="loginBusy||!email||!password">{{loginBusy?labels.signingIn:labels.signIn}}</button>
        <button v-if="loginBusy" type="button" :disabled="cancellingLogin" class="min-h-11 w-full rounded-lg border border-border px-4 text-sm disabled:opacity-50" @click="cancelLogin">
          {{labels.cancelLogin}}
        </button>
      </form>
      <p v-if="loginMessage" class="text-sm text-muted-foreground" role="status">{{loginStatus}}</p>
      <button v-if="state.kind==='unavailable'||loginMessage==='unconfirmed'" type="button"
        class="min-h-11 w-full rounded-lg border border-border px-4 text-sm font-medium hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:opacity-50"
        :disabled="busy||loginBusy" @click="refresh">
        {{state.kind==='unavailable'?labels.refresh:labels.checkResult}}
      </button>
    </div>
    <p v-if="error" role="alert" class="mt-3 text-sm text-destructive">
      {{logoutFailure==="forbidden"?labels.forbidden:logoutFailure==="unavailable"?labels.revokedFailure:labels.logoutError}}
    </p>
  </section>
</template>
