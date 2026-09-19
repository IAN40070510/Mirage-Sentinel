"use server"

import { sdk } from "@lib/config"
import { HttpTypes } from "@medusajs/types"

export async function listProductOptions() {
  return sdk.client.fetch<{ product_options?: HttpTypes.StoreProductOption[] }>(
    "/store/product-options",
    { method: "GET", query: { is_exclusive: false, fields: "*values" } }
  )
}
