import { NextRequest, NextResponse } from "next/server"

export async function middleware(request: NextRequest) {
  const visitor = request.cookies.get("visitor_id")?.value
  const epoch = request.headers.get("x-routing-epoch")
  if (!visitor || !epoch) return new NextResponse("Service unavailable", { status: 503 })
  const response = await fetch(`${process.env.COMMERCE_GATEWAY_URL}/store/regions`, {
    headers: {
      cookie: `visitor_id=${visitor}`,
      "x-routing-epoch": epoch,
      "x-parent-request-id": request.headers.get("x-parent-request-id") || "",
      "x-client-ip": request.headers.get("x-client-ip") || "",
      "x-storefront-token": process.env.STOREFRONT_TOKEN || "",
    },
    cache: "no-store",
  })
  if (!response.ok) return new NextResponse("Please reload the page", { status: 503 })
  const { regions } = await response.json()
  const countries: string[] = regions.flatMap((r: { countries: { iso_2: string }[] }) => r.countries.map(c => c.iso_2))
  const current = request.nextUrl.pathname.split("/")[1]?.toLowerCase()
  if (countries.includes(current)) return NextResponse.next()
  const country = countries.includes("dk") ? "dk" : countries[0]
  if (!country) return new NextResponse("Store unavailable", { status: 503 })
  const url = request.nextUrl.clone()
  url.host = request.headers.get("x-forwarded-host") || request.headers.get("host") || url.host
  url.protocol = (request.headers.get("x-forwarded-proto") || "http") + ":"
  url.pathname = `/${country}${request.nextUrl.pathname === "/" ? "" : request.nextUrl.pathname}`
  return NextResponse.redirect(url, 307)
}
export const config = {
  matcher: ["/((?!api|_next|favicon.ico|images|assets|.*\\.).*)"],
}
