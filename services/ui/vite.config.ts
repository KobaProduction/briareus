import { fileURLToPath, URL } from "node:url"
import { readFileSync } from "node:fs"
import { env } from "node:process"

import tailwindcss from "@tailwindcss/vite"
import vue from "@vitejs/plugin-vue"
import { defineConfig } from "vite"
import { localHttpProxy, LOCAL_HTTP_PROXY_ENV } from "./local-http-proxy"

/** Immutable UI SOURCE PACKAGE version, not guessed deployment or server
 * identity. No Git credentials, Team OTLP secrets, container TZ or ENV. */
const manifest=JSON.parse(readFileSync(fileURLToPath(new URL("./package.json",import.meta.url)),"utf8")) as {version:string}
if(!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(manifest.version)){
  throw new Error("Invalid Briareus package version")
}
/** Opt-in native HTTP development: no Docker, no TLS and no public remote
 * provider endpoints. Only existing local Gateway on 127.0.0.1:18925.
 * This does NOT enable secure OAuth callbacks or bypass server permissions.
 */
export default defineConfig(({mode})=>({
  define:{__BRIAREUS_UI_PACKAGE_VERSION__:JSON.stringify(manifest.version)},
  // One public Gateway serves the Panel at /panel/; no /api/ assets.
  base:"/panel/",
  plugins:[vue(),tailwindcss()],
  resolve:{alias:{"@":fileURLToPath(new URL("./src",import.meta.url))}},
  server:{host:"127.0.0.1",proxy:localHttpProxy(env[LOCAL_HTTP_PROXY_ENV]??(mode==="local-testing"?"panel":undefined))},
  preview:{host:"127.0.0.1",proxy:localHttpProxy(env[LOCAL_HTTP_PROXY_ENV])},
}))
