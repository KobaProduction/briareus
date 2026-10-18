import {afterEach,describe,expect,it} from "bun:test"
import {checkNativePrelogin,cancelNativePrelogin} from "../src/features/platform/api/native-prelogin-control"

const original=globalThis.fetch
afterEach(()=>{globalThis.fetch=original})
function response(status:number,payload:unknown={}):Response{
  return new Response(JSON.stringify(payload),{status,headers:{"Content-Type":"application/json"}})
}
const supported={protocol:"rauthy-native-v1",first_factor:"password",pow:"client-solved",cancel:true,continuations:[]}

describe("Backend native prelogin capability and explicit cancellation",()=>{
  it("accepts only exact cookie-bound native v1 capability without identity inference",async()=>{
    let requested="",options:RequestInit={}
    globalThis.fetch=async(input,init)=>{requested=String(input);options=init??{};return response(200,supported)}
    expect(await checkNativePrelogin(new AbortController().signal)).toEqual({kind:"supported"})
    expect(requested).toBe("/api/v1/auth/capabilities")
    expect(options.method).toBe("GET")
    expect(options.credentials).toBe("same-origin")
    expect(options.mode).toBe("same-origin")
    expect(options.redirect).toBe("error")
    expect(options.body).toBeUndefined()
  })
  it("accepts only the exact server-announced OTP continuation without inferring login",async()=>{
    let requests=0
    globalThis.fetch=async()=>{requests++;return response(200,{...supported,continuations:["otp"]})}
    expect(await checkNativePrelogin(new AbortController().signal)).toEqual({kind:"supported"})
    expect(requests).toBe(1)
  })
  it("rejects unknown/overbroad/partial version replies without promoting Init",async()=>{
    for(const payload of [
      {...supported,protocol:"rauthy-native-v2"},
      {...supported,continuations:["otp_pending"]},
      {...supported,continuations:["webauthn"]},
      {...supported,continuations:["otp","otp"]},
      {...supported,continuations:["otp","webauthn"]},
      {...supported,continuations:["OTP"]},
      {...supported,continuations:["otp",null]},
      {...supported,continuations:"otp"},
      {...supported,authenticated:true},
      {...supported,pow:"server-computed"},
      {...supported,cancel:false},
      {protocol:"rauthy-native-v1"},
    ]){
      globalThis.fetch=async()=>response(200,payload)
      expect((await checkNativePrelogin(new AbortController().signal)).kind).toBe("invalid")
    }
  })
  it("does not fetch after preflight cancellation or treat a 503 as availability",async()=>{
    let count=0
    globalThis.fetch=async()=>{count++;return response(503,{error:{code:"NATIVE_DISABLED"}})}
    expect((await checkNativePrelogin(AbortSignal.abort())).kind).toBe("unavailable")
    expect(count).toBe(0)
    expect(await checkNativePrelogin(new AbortController().signal)).toEqual({kind:"unavailable",code:"NATIVE_DISABLED"})
    expect(count).toBe(1)
  })
  it("refuses huge or non-JSON native capabilities without allocating Init",async()=>{
    let calls=0
    for(const reply of [
      new Response(JSON.stringify({...supported,noise:"x".repeat(100_000)}),
        {status:200,headers:{"Content-Type":"application/json"}}),
      new Response(JSON.stringify(supported),
        {status:200,headers:{"Content-Type":"text/html"}}),
      new Response(JSON.stringify(supported),
        {status:200,headers:{"Content-Type":"application/json","Content-Length":"5000"}}),
    ]){
      globalThis.fetch=async()=>{calls++;return reply}
      expect((await checkNativePrelogin(new AbortController().signal)).kind).toBe("unavailable")
    }
    expect(calls).toBe(3)
  })
  it("bounds malformed or oversized native error JSON before decoding it",async()=>{
    globalThis.fetch=async()=>new Response("x".repeat(100_000),{
      status:503,headers:{"Content-Type":"application/json"},
    })
    expect(await checkNativePrelogin(new AbortController().signal))
      .toEqual({kind:"unavailable",code:"NATIVE_UNAVAILABLE"})
  })
  it("interrupts a stalled capabilities body without accidentally accepting a 200",async()=>{
    let cancelled=0
    const reply=new ReadableStream<Uint8Array>({cancel(){cancelled++}})
    const request=new AbortController()
    globalThis.fetch=async()=>new Response(reply,{status:200,headers:{"Content-Type":"application/json"}})
    const pending=checkNativePrelogin(request.signal)
    setTimeout(()=>request.abort(),20)
    const result=await Promise.race([pending,new Promise<"hung">(resolve=>setTimeout(()=>resolve("hung"),250))])
    expect(result).toEqual({kind:"unavailable",code:"NATIVE_CAPABILITIES_UNAVAILABLE"})
    expect(cancelled).toBe(1)
  })
  it("returns uncertain cleanup if a native cancellation error body stalls then aborts",async()=>{
    let cancelled=0
    const reply=new ReadableStream<Uint8Array>({cancel(){cancelled++}})
    const request=new AbortController()
    globalThis.fetch=async()=>new Response(reply,{status:503,headers:{"Content-Type":"application/json"}})
    const pending=cancelNativePrelogin(request.signal)
    setTimeout(()=>request.abort(),20)
    const result=await Promise.race([pending,new Promise<"hung">(resolve=>setTimeout(()=>resolve("hung"),250))])
    expect(result).toEqual({kind:"unavailable",code:"NATIVE_CANCEL_UNCERTAIN"})
    expect(cancelled).toBe(1)
  })
  it("sends only an exact empty JSON POST on explicit native cancellation",async()=>{
    let path="",options:RequestInit={}
    globalThis.fetch=async(input,init)=>{path=String(input);options=init??{};return new Response(null,{status:204})}
    expect(await cancelNativePrelogin(new AbortController().signal)).toEqual({kind:"cancelled"})
    expect(path).toBe("/api/v1/auth/cancel")
    expect(options.method).toBe("POST")
    expect(options.body).toBe("{}")
    expect(options.credentials).toBe("same-origin")
    expect(options.redirect).toBe("error")
  })
  it("does not pretend cancellation succeeded on denied, unavailable or late interrupted response",async()=>{
    globalThis.fetch=async()=>response(503,{error:{code:"NATIVE_CANCEL_UNAVAILABLE"}})
    expect(await cancelNativePrelogin(new AbortController().signal)).toEqual({kind:"unavailable",code:"NATIVE_CANCEL_UNAVAILABLE"})
    globalThis.fetch=async()=>response(403,{error:{code:"NATIVE_ORIGIN_OR_REQUEST_DENIED"}})
    expect((await cancelNativePrelogin(new AbortController().signal)).kind).toBe("forbidden")
    const controller=new AbortController()
    globalThis.fetch=async()=>{controller.abort();return new Response(null,{status:204})}
    expect((await cancelNativePrelogin(controller.signal)).kind).toBe("unavailable")
  })
})
