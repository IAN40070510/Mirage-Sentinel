import { MedusaContainer } from "@medusajs/framework"
import { ContainerRegistrationKeys, Modules, ProductStatus } from "@medusajs/framework/utils"
import { createCollectionsWorkflow, createProductsWorkflow, createInventoryLevelsWorkflow } from "@medusajs/medusa/core-flows"

// Additive catalog migration: initial-data-seed runs first on new installations.
// Each realm runs this independently; no IDs or connections cross database boundaries.
const imageBase = "https://medusa-public-images.s3.eu-west-1.amazonaws.com/"
const catalog = [
  { handle: "essential-black-tee", title: "經典黑色棉質 T 恤", category: "Shirts", image: "tee-black", eur: 19, usd: 22, weight: 220, description: "日常衣櫥的基本款黑色短袖，俐落輪廓適合單穿或層次搭配。" },
  { handle: "essential-white-tee", title: "經典白色棉質 T 恤", category: "Shirts", image: "tee-white", eur: 19, usd: 22, weight: 220, description: "清爽白色短袖上衣，適合搭配牛仔褲、休閒褲或作為內搭。" },
  { handle: "relaxed-black-tee", title: "寬鬆黑色休閒 T 恤", category: "Shirts", image: "tee-black", eur: 24, usd: 28, weight: 260, description: "寬鬆風格的黑色短袖，適合週末休閒與街頭層次穿搭。" },
  { handle: "relaxed-white-tee", title: "寬鬆白色休閒 T 恤", category: "Shirts", image: "tee-white", eur: 24, usd: 28, weight: 260, description: "簡約白色短袖，以輕鬆的穿搭風格為主，搭配長褲與短褲皆宜。" },
  { handle: "classic-crew-sweatshirt", title: "經典圓領衛衣", category: "Sweatshirts", image: "sweatshirt-vintage", eur: 39, usd: 45, weight: 520, description: "復古色調的圓領長袖衛衣，適合日常通勤與季節交替時的層次搭配。" },
  { handle: "weekend-crew-sweatshirt", title: "週末休閒衛衣", category: "Sweatshirts", image: "sweatshirt-vintage", eur: 42, usd: 49, weight: 550, description: "以休閒搭配為主的長袖衛衣，可與同色系長褲組合成完整造型。" },
  { handle: "layering-crew-sweatshirt", title: "日常層次圓領衛衣", category: "Sweatshirts", image: "sweatshirt-vintage", eur: 45, usd: 52, weight: 580, description: "簡潔圓領設計，適合搭配內搭 T 恤，建立日常的多層次衣著。" },
  { handle: "classic-gray-joggers", title: "經典灰色休閒長褲", category: "Pants", image: "sweatpants-gray", eur: 35, usd: 40, weight: 450, description: "灰色休閒長褲，適合搭配素色 T 恤或衛衣，打造簡約日常造型。" },
  { handle: "weekend-gray-joggers", title: "週末灰色運動長褲", category: "Pants", image: "sweatpants-gray", eur: 39, usd: 45, weight: 480, description: "以輕鬆外出與居家穿搭為主的灰色長褲，容易搭配不同色系上衣。" },
  { handle: "everyday-gray-joggers", title: "日常灰色束口長褲", category: "Pants", image: "sweatpants-gray", eur: 42, usd: 48, weight: 500, description: "束口輪廓的灰色長褲，適合與圓領衛衣搭配成套休閒造型。" },
  { handle: "classic-vintage-shorts", title: "復古休閒短褲", category: "Pants", image: "shorts-vintage", eur: 25, usd: 29, weight: 250, description: "復古色調的休閒短褲，適合暖季穿搭，可搭配黑色或白色 T 恤。" },
  { handle: "weekend-vintage-shorts", title: "週末輕鬆短褲", category: "Pants", image: "shorts-vintage", eur: 29, usd: 34, weight: 280, description: "日常與週末外出的短褲選擇，搭配簡約上衣即可完成休閒造型。" },
]
const sizes = ["S", "M", "L", "XL"]

export default async function clothingCatalog({ container }: { container: MedusaContainer }) {
  const query = container.resolve(ContainerRegistrationKeys.QUERY)
  const logger = container.resolve(ContainerRegistrationKeys.LOGGER)
  const inventory = container.resolve(Modules.INVENTORY)
  const { data: stores } = await query.graph({ entity: "store", fields: ["default_sales_channel_id"] })
  const { data: profiles } = await query.graph({ entity: "shipping_profile", fields: ["id", "type"] })
  const { data: locations } = await query.graph({ entity: "stock_location", fields: ["id", "name"] })
  const { data: categories } = await query.graph({ entity: "product_category", fields: ["id", "name"] })
  const channel = stores[0]?.default_sales_channel_id
  const profile = profiles.find((item) => item.type === "default")
  const location = locations.find((item) => item.name === "European Warehouse")
  if (!channel || !profile || !location || catalog.some((item) => !categories.some((cat) => cat.name === item.category))) {
    throw new Error("Initialize the store, default shipping profile, warehouse and apparel categories before adding clothing")
  }
  const { data: collections } = await query.graph({ entity: "product_collection", fields: ["id"], filters: { handle: "clothing-essentials" } })
  let collectionId = collections[0]?.id
  if (!collectionId) {
    const { result } = await createCollectionsWorkflow(container).run({ input: { collections: [{ title: "服裝精選", handle: "clothing-essentials" }] } })
    collectionId = result[0].id
  }
  const { data: existing } = await query.graph({ entity: "product", fields: ["handle"], filters: { handle: catalog.map((item) => item.handle) } })
  const handles = new Set(existing.map((item) => item.handle))
  const missing = catalog.filter((item) => !handles.has(item.handle))
  if (missing.length) {
    await createProductsWorkflow(container).run({ input: { products: missing.map((item) => ({
      title: item.title, handle: item.handle,
      description: item.description + " 商品圖片為示意，沿用商店既有服裝素材。",
      status: ProductStatus.PUBLISHED, weight: item.weight,
      collection_id: collectionId,
      category_ids: [categories.find((cat) => cat.name === item.category)!.id],
      shipping_profile_id: profile.id,
      thumbnail: imageBase + item.image + "-front.png",
      images: ["front", "back"].map((side) => ({ url: imageBase + item.image + "-" + side + ".png" })),
      options: [{ title: "Size", values: sizes }],
      variants: sizes.map((size) => ({
        title: size, sku: "APPAREL-" + item.handle.toUpperCase() + "-" + size,
        options: { Size: size }, manage_inventory: true, allow_backorder: false,
        prices: [{ currency_code: "eur", amount: item.eur }, { currency_code: "usd", amount: item.usd }],
      })),
      sales_channels: [{ id: channel }],
      metadata: { catalog_batch: "clothing-2026-11", image_kind: "illustrative-existing-store-assets" },
    })) } })
  }
  // Repair only missing inventory levels on retry; never reset existing stock or reservations.
  const skus = catalog.flatMap((item) => sizes.map((size) => "APPAREL-" + item.handle.toUpperCase() + "-" + size))
  const { data: items } = await query.graph({ entity: "inventory_item", fields: ["id"], filters: { sku: skus } })
  if (items.length !== skus.length) throw new Error("Clothing inventory items are incomplete")
  const levels = await inventory.listInventoryLevels({ inventory_item_id: items.map((item) => item.id), location_id: location.id }, { take: 1000 })
  const stocked = new Set(levels.map((level) => level.inventory_item_id))
  const inventoryLevels = items.filter((item) => !stocked.has(item.id)).map((item) => ({ inventory_item_id: item.id, location_id: location.id, stocked_quantity: 100 }))
  if (inventoryLevels.length) await createInventoryLevelsWorkflow(container).run({ input: { inventory_levels: inventoryLevels } })
  logger.info(`Clothing catalog ready: ${catalog.length} products, ${skus.length} size variants; added ${missing.length} products and ${inventoryLevels.length} stock levels`)
}
