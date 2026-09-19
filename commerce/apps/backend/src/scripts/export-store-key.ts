import { ExecArgs } from "@medusajs/framework/types"
import { ContainerRegistrationKeys, MedusaError } from "@medusajs/framework/utils"

export default async function exportStoreKey({ container }: ExecArgs) {
  const query = container.resolve(ContainerRegistrationKeys.QUERY)
  const { data } = await query.graph({
    entity: "api_key",
    fields: ["token", "type"],
    filters: { type: "publishable" },
  })
  if (!data[0]?.token) throw new MedusaError(MedusaError.Types.NOT_FOUND, "No publishable API key: run db:migrate first")
  console.log(`STORE_KEY=${data[0].token}`)
}
