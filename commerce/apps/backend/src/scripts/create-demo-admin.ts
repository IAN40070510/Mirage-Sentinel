import { ExecArgs } from "@medusajs/framework/types"
import { ContainerRegistrationKeys, MedusaError, Modules } from "@medusajs/framework/utils"
import { createUsersWorkflow } from "@medusajs/medusa/core-flows"

export default async function createDemoAdmin({ container }: ExecArgs) {
  const email = process.env.ADMIN_EMAIL
  const password = process.env.ADMIN_PASSWORD
  if (!email || !password || password.length < 32) {
    throw new MedusaError(MedusaError.Types.INVALID_DATA, "Set ADMIN_EMAIL and a generated ADMIN_PASSWORD")
  }
  const query = container.resolve(ContainerRegistrationKeys.QUERY)
  const { data: existing } = await query.graph({ entity: "user", fields: ["id"], filters: { email } })
  if (existing.length) return
  const { result: users } = await createUsersWorkflow(container).run({ input: { users: [{ email }] } })
  const auth = container.resolve(Modules.AUTH)
  const { authIdentity, error } = await auth.register("emailpass", { body: { email, password } })
  if (error || !authIdentity) {
    throw new MedusaError(MedusaError.Types.INVALID_DATA, "Could not create admin identity")
  }
  await auth.updateAuthIdentities({ id: authIdentity.id, app_metadata: { user_id: users[0].id } })
}
