/** HTTP local-first bridge for native Frontend development ONLY.
 *
 * Deliberately provides NO OAuth identity, cookie, grant, port discovery,
 * public Dev URL, origin bypass or fake API response. It forwards same-origin
 * /api/* to the existing, independently authorized LOCAL Gateway.
 * Runtime and Backend remain the ONLY owners of authentication semantics.
 */
import type { ProxyOptions } from "vite"

export const LOCAL_HTTP_PROXY_ENV="BRIAREUS_LOCAL_HTTP_API_PROXY"
export const LOCAL_GATEWAY_URL="http://127.0.0.1:18925"
export const LOCAL_GATEWAY_HOST="briareus.koba-nexus.ru"

/** A recognized explicit opt-in; no arbitrary URL or remote proxy allowed. */
export function localHttpProxy(enabled: string | undefined): Record<string,ProxyOptions> | undefined {
  if(enabled===undefined||enabled==="")return undefined
  if(enabled!=="gateway"&&enabled!=="panel")throw new Error(
    `${LOCAL_HTTP_PROXY_ENV} only supports 'gateway' or 'panel' on 127.0.0.1`
  )
  return {
    "/api/":{
      target:enabled==="panel"?"http://127.0.0.1:18000":LOCAL_GATEWAY_URL,
      changeOrigin:false,
      // Existing Gateway has an exact, source-owned canonical Host allowlist.
      // This is ONLY local fixed loopback forwarding; it does NOT relax a
      // write Origin check or produce/authorize a cookie or bearer.
      headers:{host:enabled==="panel"?"127.0.0.1":LOCAL_GATEWAY_HOST},
      timeout:8000,
      proxyTimeout:8000,
    },
  }
}
