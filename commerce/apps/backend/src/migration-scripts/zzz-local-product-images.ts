import { MedusaContainer } from "@medusajs/framework"
import { ContainerRegistrationKeys } from "@medusajs/framework/utils"
import { updateProductsWorkflow } from "@medusajs/medusa/core-flows"

const base = "/images/catalog-v2/"
const originals: Record<string, string[]> = {
  "t-shirt": ["tee-black-front.png", "tee-black-back.png", "tee-white-front.png", "tee-white-back.png"],
  "sweatshirt": ["sweatshirt-vintage-front.png", "sweatshirt-vintage-back.png"],
  "sweatpants": ["sweatpants-gray-front.png", "sweatpants-gray-back.png"],
  "shorts": ["shorts-vintage-front.png", "shorts-vintage-back.png"],
}
const clothing = [
  "essential-black-tee", "essential-white-tee", "relaxed-black-tee", "relaxed-white-tee",
  "classic-crew-sweatshirt", "weekend-crew-sweatshirt", "layering-crew-sweatshirt",
  "classic-gray-joggers", "weekend-gray-joggers", "everyday-gray-joggers",
  "classic-vintage-shorts", "weekend-vintage-shorts",
]

export default async function localProductImages({ container }: { container: MedusaContainer }) {
  const query = container.resolve(ContainerRegistrationKeys.QUERY)
  const logger = container.resolve(ContainerRegistrationKeys.LOGGER)
  const handles = [...Object.keys(originals), ...clothing]
  const { data: products } = await query.graph({
    entity: "product", fields: ["id", "handle", "description", "metadata"],
    filters: { handle: handles },
  })
  if (products.length !== handles.length) throw new Error("Expected catalog products before updating their images")
  // Update only image presentation and its disclosure, never variants, prices or stock.
  await updateProductsWorkflow(container).run({ input: { products: products.map((product) => {
    const generated = clothing.includes(product.handle)
    const files = originals[product.handle] || [product.handle + ".png"]
    const description = generated
      ? (product.description || "").replace("商品圖片為示意，沿用商店既有服裝素材。", "")
          .replace("商品圖片為 AI 生成的款式示意圖，非實品攝影。", "").trim()
          + " 商品圖片為 AI 生成的款式示意圖，非實品攝影。"
      : product.description
    return {
      id: product.id, thumbnail: base + files[0],
      images: files.map((file) => ({ url: base + file })), description,
      metadata: { ...product.metadata, image_kind: generated ? "ai-generated-product-illustration" : "local-original-store-asset", image_revision: "catalog-v2" },
    }
  }) } })
  logger.info(`Updated ${products.length} products with local catalog images; original stock and prices preserved`)
}
