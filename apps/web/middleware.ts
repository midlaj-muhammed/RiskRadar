import { NextResponse, type NextRequest } from "next/server";

/**
 * Optional dashboard/API auth gate. When RISKRADAR_DASHBOARD_TOKEN is set, every
 * request must present it (cookie `rr_token`, `x-riskradar-token` header,
 * `Authorization: Bearer`, or `?token=`); otherwise 401. When unset, the app is
 * open (local dev default). The Telegram webhook is exempt — it authenticates via
 * its own X-Telegram-Bot-Api-Secret-Token header.
 *
 * Self-contained (no @riskradar/core import) so it runs in the edge runtime.
 */
export function middleware(request: NextRequest) {
  const token = process.env.RISKRADAR_DASHBOARD_TOKEN;
  if (!token) return NextResponse.next();

  const pathname = request.nextUrl.pathname;
  if (pathname.startsWith("/api/integrations/telegram/webhook")) return NextResponse.next();

  const provided =
    request.cookies.get("rr_token")?.value ||
    request.headers.get("x-riskradar-token") ||
    (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "") ||
    request.nextUrl.searchParams.get("token") ||
    "";

  if (provided && provided === token) return NextResponse.next();

  const wantsJson = pathname.startsWith("/api/");
  return new NextResponse(
    wantsJson
      ? JSON.stringify({ error: { code: "unauthorized", message: "RiskRadar dashboard token required.", details: {} } })
      : "Unauthorized — RiskRadar dashboard token required.",
    { status: 401, headers: { "content-type": wantsJson ? "application/json" : "text/plain" } }
  );
}

export const config = {
  // Gate everything except Next internals/static assets.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"]
};
