import "server-only"
import { cookies, headers as requestHeaders } from "next/headers"
import Medusa, { FetchArgs, FetchInput } from "@medusajs/js-sdk"

// Server-rendered pages and server actions always pass through the gateway.
export const sdk = new Medusa({
  baseUrl: process.env.COMMERCE_GATEWAY_URL || "http://gateway:8000/_api",
  debug: false,
  publishableKey: "gateway-managed",
  auth: { type: "jwt", jwtTokenStorageMethod: "nostore" },
})
const originalFetch = sdk.client.fetch.bind(sdk.client)
sdk.client.fetch = async <T>(input: FetchInput, init?: FetchArgs): Promise<T> => {
  const incoming = await requestHeaders()
  const visitor = (await cookies()).get("visitor_id")?.value
  const epoch = incoming.get("x-routing-epoch")
  if (!visitor || !epoch) throw new Error("Missing visitor context")
  return originalFetch(input, {
    ...init,
    cache: "no-store",
    next: undefined,
    headers: {
      ...init?.headers,
      cookie: `visitor_id=${visitor}`,
      "x-routing-epoch": epoch,
      "x-parent-request-id": incoming.get("x-parent-request-id") || "",
      "x-client-ip": incoming.get("x-client-ip") || "",
      "x-storefront-token": process.env.STOREFRONT_TOKEN || "",
    },
  })
}
