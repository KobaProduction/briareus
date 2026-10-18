import {describe,expect,it} from "bun:test"
import {prepareNativeRauthyLogin} from "../src/features/platform/api/native-rauthy"

function apiReply(status:number,body:unknown):Response {
  return new Response(JSON.stringify(body),{status,headers:{"Content-Type":"application/json"}})
}
function scopeTest(responses:Response[],run:(requests:{path:string;options:RequestInit}[])=>Promise<void>):Promise<void>{
  const original=globalThis.fetch
  const requests:{path:string;options:RequestInit}[]=[]
  let count=0
  globalThis.fetch=async (input:RequestInfo|URL,init?:RequestInit):Promise<Response>=>{
    requests.push({path:String(input),options:init??{}})
    return responses[count++]??apiReply(503,{error:{code:"NATIVE_UNAVAILABLE"}})
  }
  return run(requests).finally(()=>{globalThis.fetch=original})
}
describe("native Rauthy credential-free handshake",()=>{
  it("checks exact same-origin Init without wasting a one-use PoW",async()=>{
    await scopeTest([
      apiReply(201,{stage:"first_factor_required",authenticated:false,expires_in:120}),
    ],async requests=>{
      const result=await prepareNativeRauthyLogin(new AbortController().signal)
      expect(result).toMatchObject({kind:"prepared",expiresIn:120})
      if(result.kind==="prepared")expect(result.expiresAt).toBeGreaterThan(Date.now())
      expect(requests.map(row=>row.path)).toEqual([
        "/api/v1/auth/start",
      ])
      for(const {options} of requests){
        expect(options.method).toBe("POST")
        expect(options.body).toBe("{}")
        expect(options.credentials).toBe("same-origin")
        expect(options.mode).toBe("same-origin")
        expect(options.redirect).toBe("error")
      }
    })
  })
  it("rejects an untrusted Init without advancing to PoW",async()=>{
    await scopeTest([apiReply(201,{stage:"first_factor_required",authenticated:true,expires_in:120})],async requests=>{
      expect(await prepareNativeRauthyLogin(new AbortController().signal))
        .toEqual({kind:"invalid",code:"NATIVE_INIT_RESPONSE_INVALID"})
      expect(requests.length).toBe(1)
    })
  })
  it("never treats provider failure or invalid success as authentication",async()=>{
    await scopeTest([apiReply(503,{error:{code:"NATIVE_INIT_UNAVAILABLE"}})],async requests=>{
      expect(await prepareNativeRauthyLogin(new AbortController().signal))
        .toEqual({kind:"unavailable",code:"NATIVE_INIT_UNAVAILABLE"})
      expect(requests.length).toBe(1)
    })
    await scopeTest([apiReply(201,{stage:"first_factor_required",authenticated:false,expires_in:120,access_token:"forged"})],async requests=>{
      expect(await prepareNativeRauthyLogin(new AbortController().signal))
        .toEqual({kind:"invalid",code:"NATIVE_INIT_RESPONSE_INVALID"})
      expect(requests.length).toBe(1)
    })
    await scopeTest([apiReply(201,{stage:"first_factor_required",authenticated:false,expires_in:301})],async requests=>{
      expect(await prepareNativeRauthyLogin(new AbortController().signal))
        .toEqual({kind:"invalid",code:"NATIVE_INIT_RESPONSE_INVALID"})
      expect(requests.length).toBe(1)
    })
    await scopeTest([apiReply(403,{error:{code:"NATIVE_ORIGIN_OR_REQUEST_DENIED"}})],async requests=>{
      expect(await prepareNativeRauthyLogin(new AbortController().signal))
        .toEqual({kind:"forbidden",code:"NATIVE_ORIGIN_OR_REQUEST_DENIED"})
      expect(requests.length).toBe(1)
    })
  })
})

describe("native transaction deadlines",()=>{
  it("subtracts response delay from preparation lifetime instead of renewing it",async()=>{
    const previous=Date.now,fetch=globalThis.fetch;let now=1_000_000
    try{
      Date.now=()=>now
      globalThis.fetch=async()=>{now+=5000;return apiReply(201,{stage:'first_factor_required',authenticated:false,expires_in:10})}
      expect(await prepareNativeRauthyLogin(new AbortController().signal)).toEqual({kind:'prepared',expiresIn:10,expiresAt:1_010_000})
    }finally{Date.now=previous;globalThis.fetch=fetch}
  })
  it("rejects an expired delayed Init and stops before a cancelled request",async()=>{
    const previous=Date.now,fetch=globalThis.fetch;let now=2_000_000,calls=0
    try{
      Date.now=()=>now
      globalThis.fetch=async()=>{calls++;now+=3000;return apiReply(201,{stage:'first_factor_required',authenticated:false,expires_in:2})}
      expect((await prepareNativeRauthyLogin(new AbortController().signal)).kind).toBe('expired')
      expect(await prepareNativeRauthyLogin(AbortSignal.abort())).toEqual({kind:'unavailable',code:'NATIVE_PREPARATION_CANCELLED'})
      expect(calls).toBe(1)
    }finally{Date.now=previous;globalThis.fetch=fetch}
  })
  it("never publishes a success returned after cancellation",async()=>{
    const fetch=globalThis.fetch,request=new AbortController()
    try{
      globalThis.fetch=async()=>{request.abort();return apiReply(201,{stage:'first_factor_required',authenticated:false,expires_in:120})}
      expect(await prepareNativeRauthyLogin(request.signal)).toEqual({kind:'unavailable',code:'NATIVE_PREPARATION_CANCELLED'})
    }finally{globalThis.fetch=fetch}
  })
})

describe("native Init monotonic lifetime",()=>{
  it("charges monotonic response delay even when the wall clock is paused",async()=>{
    const {spyOn}=await import('bun:test')
    const now=Date.now(),wall=spyOn(Date,'now').mockReturnValue(now)
    let elapsed=100
    const monotonic=spyOn(performance,'now').mockImplementation(()=>elapsed)
    const original=globalThis.fetch
    try{
      globalThis.fetch=async()=>{elapsed+=2001;return apiReply(201,{stage:'first_factor_required',authenticated:false,expires_in:2})}
      expect((await prepareNativeRauthyLogin(new AbortController().signal)).kind).toBe('expired')
    }finally{globalThis.fetch=original;monotonic.mockRestore();wall.mockRestore()}
  })
})

describe("bounded source-only native Init replies",()=>{
  it("does not accept an oversized HTTP201 as a prepared login or request a PoW",async()=>{
    await scopeTest([apiReply(201,{
      stage:"first_factor_required",authenticated:false,expires_in:120,
      noise:"Z".repeat(25_000),
    })],async requests=>{
      expect((await prepareNativeRauthyLogin(new AbortController().signal)).kind).toBe("unavailable")
      expect(requests.map(row=>row.path)).toEqual(["/api/v1/auth/start"])
    })
  })
  it("does not decode a giant HTTP503 body into a retry instruction",async()=>{
    await scopeTest([apiReply(503,{error:{code:"NATIVE_UNAVAILABLE"},padding:"Y".repeat(15_000)})],
      async requests=>{
        expect(await prepareNativeRauthyLogin(new AbortController().signal))
          .toEqual({kind:"unavailable",code:"NATIVE_UNAVAILABLE"})
        expect(requests).toHaveLength(1)
      })
  })
})

import {submitNativePasswordLogin,usableNativePowDeadline} from "../src/features/platform/api/native-first-factor"

const nativeChallenge=()=>"1:10:"+(Math.floor(Date.now()/1000)+120)+":"+"A".repeat(16)+":"+"B".repeat(43)+":"
const nativeCapability={protocol:"rauthy-native-v1",first_factor:"password",pow:"client-solved",cancel:true,continuations:["otp"]}
const nativeInit={stage:"first_factor_required",authenticated:false,expires_in:120}
const nativeReceipt={stage:"authenticated",authenticated:true,authority:"rauthy",platform_membership_verified:false,permissions:[]}

async function nativeBrowserFixture(replies:Response[],test:(calls:{url:string;init:RequestInit}[])=>Promise<void>):Promise<void>{
  const oldFetch=globalThis.fetch
  const oldWindow=Object.getOwnPropertyDescriptor(globalThis,"window")
  const oldWorker=Object.getOwnPropertyDescriptor(globalThis,"Worker")
  const calls:{url:string;init:RequestInit}[]=[]
  let idx=0
  Object.defineProperty(globalThis,"window",{configurable:true,value:{location:{protocol:"https:"},isSecureContext:true}})
  Object.defineProperty(globalThis,"Worker",{configurable:true,value:class {
    onmessage:((event:{data:unknown})=>void)|null=null
    postMessage(challenge:unknown){queueMicrotask(()=>this.onmessage?.({data:{kind:"solved",work:String(challenge)+"123"}}))}
    terminate(){}
  }})
  globalThis.fetch=async (url,init)=>{
    calls.push({url:String(url),init:init??{}})
    return replies[idx++]??apiReply(503,{error:{code:"UNEXPECTED"}})
  }
  try{await test(calls)}
  finally{
    globalThis.fetch=oldFetch
    if(oldWindow)Object.defineProperty(globalThis,"window",oldWindow)
    else Reflect.deleteProperty(globalThis,"window")
    if(oldWorker)Object.defineProperty(globalThis,"Worker",oldWorker)
    else Reflect.deleteProperty(globalThis,"Worker")
  }
}
describe("native password sign-in from explicit user action",()=>{
  it("sends only expected same-origin steps and never treats first factor as a User grant",async()=>{
    await nativeBrowserFixture([
      apiReply(200,nativeCapability),apiReply(201,nativeInit),
      apiReply(200,{challenge:nativeChallenge(),authenticated:false}),
      apiReply(200,nativeReceipt),
    ],async calls=>{
      const outcome=await submitNativePasswordLogin("fixture@example.invalid","fixture-only-password",new AbortController().signal)
      expect(outcome).toEqual({kind:"session_issued"})
      expect(calls.map(x=>x.url)).toEqual([
        "/api/v1/auth/capabilities","/api/v1/auth/start","/api/v1/auth/pow","/api/v1/auth/first-factor",
      ])
      expect(calls.map(x=>x.init.method)).toEqual(["GET","POST","POST","POST"])
      for(const x of calls){
        expect(x.init.credentials).toBe("same-origin")
        expect(x.init.redirect).toBe("error")
      }
      const body=JSON.parse(String(calls[3]?.init.body))
      expect(Object.keys(body).sort()).toEqual(["email","password","pow"])
      expect(body.email).toBe("fixture@example.invalid")
      expect(body.password).toBe("fixture-only-password")
      expect(body.pow).toMatch(/^1:10:\d{10}:[A-Z]{16}:[A-Z]{43}:\d+$/)
      expect(outcome).not.toHaveProperty("identity")
    })
  })
  it("classifies offered email OTP HTTP202 as required MFA, never signed in",async()=>{
    await nativeBrowserFixture([
      apiReply(200,nativeCapability),apiReply(201,nativeInit),
      apiReply(200,{challenge:nativeChallenge(),authenticated:false}),
      apiReply(202,{stage:"otp_pending",authenticated:false,continuation_available:true,
        methods:[{index:0,kind:"email"}]}),
    ],async calls=>{
      expect(await submitNativePasswordLogin("fixture@example.invalid","fixture-only-password",
        new AbortController().signal)).toEqual({kind:"continuation_unavailable",stage:"otp_pending"})
      expect(calls.map(call=>call.url)).toEqual([
        "/api/v1/auth/capabilities","/api/v1/auth/start","/api/v1/auth/pow","/api/v1/auth/first-factor",
      ])
    })
  })
  it("rejects unknown or forged OTP continuation formats",async()=>{
    await nativeBrowserFixture([
      apiReply(200,nativeCapability),apiReply(201,nativeInit),
      apiReply(200,{challenge:nativeChallenge(),authenticated:false}),
      apiReply(202,{stage:"otp_pending",authenticated:false,continuation_available:true,
        methods:[{index:0,kind:"webauthn"}]}),
    ],async()=>{
      expect(await submitNativePasswordLogin("fixture@example.invalid","fixture-only-password",
        new AbortController().signal)).toEqual({kind:"unavailable",code:"NATIVE_CONTINUATION_INVALID"})
    })
  })
  it("returns unsupported MFA, not signed in, on Backend 409",async()=>{
    await nativeBrowserFixture([
      apiReply(200,nativeCapability),apiReply(201,nativeInit),
      apiReply(200,{challenge:nativeChallenge(),authenticated:false}),
      apiReply(409,{stage:"otp_pending",authenticated:false,continuation_available:false,restart_required:true}),
    ],async calls=>{
      expect(await submitNativePasswordLogin("fixture@example.invalid","fixture-only-password",new AbortController().signal))
        .toEqual({kind:"continuation_unavailable",stage:"otp_pending"})
      expect(calls.filter(x=>x.url.endsWith("/first-factor"))).toHaveLength(1)
    })
  })
  it("refuses forged 200 response and preserves uncertainty after aborted POST",async()=>{
    await nativeBrowserFixture([
      apiReply(200,nativeCapability),apiReply(201,nativeInit),
      apiReply(200,{challenge:nativeChallenge(),authenticated:false}),
      apiReply(200,{...nativeReceipt,access_token:"forged"}),
    ],async calls=>{
      expect((await submitNativePasswordLogin("fixture@example.invalid","fixture-only-password",new AbortController().signal)).kind)
        .toBe("uncertain")
      expect(calls).toHaveLength(4)
    })
  })
  it("never issues an Init from unavailable capabilities or a preaborted signal",async()=>{
    await nativeBrowserFixture([apiReply(503,{error:{code:"NATIVE_UNAVAILABLE"}})],async calls=>{
      expect((await submitNativePasswordLogin("fixture@example.invalid","fixture-only-password",new AbortController().signal)).kind)
        .toBe("unavailable")
      expect((await submitNativePasswordLogin("fixture@example.invalid","fixture-only-password",AbortSignal.abort())).kind)
        .toBe("cancelled")
      expect(calls.map(x=>x.url)).toEqual(["/api/v1/auth/capabilities"])
    })
  })
})


describe("provider PoW's independent 30-second expiry gate",()=>{
  it("allows fresh difficulty19 results and refuses expiry near the POST boundary",()=>{
    const observed=1_798_000_000_000,mono=1000
    const challenge="1:19:"+String(Math.floor(observed/1000)+30)+":"+"A".repeat(16)+":"+"B".repeat(43)+":"
    expect(usableNativePowDeadline(challenge,observed,mono,observed+20_000,mono+20_000)).toBe(true)
    expect(usableNativePowDeadline(challenge,observed,mono,observed+28_000,mono+28_000)).toBe(true)
    expect(usableNativePowDeadline(challenge,observed,mono,observed+29_000,mono+29_000)).toBe(false)
    expect(usableNativePowDeadline(challenge,observed,mono,observed+31_000,mono+31_000)).toBe(false)
  })
  it("does not resurrect a consumed public challenge after device clock rollback",()=>{
    const observed=1_798_000_000_000,mono=1000
    const challenge="1:19:"+String(Math.floor(observed/1000)+30)+":"+"A".repeat(16)+":"+"B".repeat(43)+":"
    expect(usableNativePowDeadline(challenge,observed,mono,observed-60_000,mono+29_000)).toBe(false)
    expect(usableNativePowDeadline(challenge,observed,mono,observed-60_000,mono+12_000)).toBe(true)
    expect(usableNativePowDeadline(challenge,observed,mono,observed-60_000,mono-1)).toBe(false)
    expect(usableNativePowDeadline("invalid",observed,mono,observed,mono)).toBe(false)
  })
})
