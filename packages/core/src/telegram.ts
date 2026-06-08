import { getEnv } from "./env";
import { RiskRadarError } from "./errors";

export async function sendTelegramApproval(input: { chatId: string; text: string; replyMarkup?: unknown }): Promise<{ messageId: string }> {
  const token = getEnv("TELEGRAM_BOT_TOKEN");
  if (!token) throw new RiskRadarError("telegram_not_configured", "Set TELEGRAM_BOT_TOKEN to send approval requests.", { requiredEnv: "TELEGRAM_BOT_TOKEN" });
  const bodyPayload: Record<string, unknown> = {
    chat_id: input.chatId,
    text: input.text
  };
  if (input.replyMarkup) bodyPayload.reply_markup = input.replyMarkup;
  const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(bodyPayload)
  });
  const body = (await response.json()) as { ok: boolean; result?: { message_id: number }; description?: string; error_code?: number };
  if (!response.ok || !body.ok || !body.result) {
    throw new RiskRadarError("telegram_send_failed", "Telegram API did not send the approval message.", {
      method: "sendMessage",
      status: response.status,
      error_code: body.error_code,
      description: body.description,
      chat_id: redactTelegramChatId(input.chatId)
    }, 502);
  }
  return { messageId: String(body.result.message_id) };
}

export interface TelegramButton {
  text: string;
  callbackData: string;
}

/**
 * Builds a Telegram inline keyboard. callback_data has a hard 64-byte limit, so
 * we use short opaque payloads (kind:id:action) — never long signed tokens.
 */
export function inlineKeyboard(rows: TelegramButton[][]): { inline_keyboard: Array<Array<{ text: string; callback_data: string }>> } {
  for (const row of rows) {
    for (const button of row) {
      if (Buffer.byteLength(button.callbackData, "utf8") > 64) {
        throw new RiskRadarError("telegram_callback_too_long", "Telegram callback_data exceeds the 64-byte limit.", { callbackData: button.callbackData.slice(0, 16) });
      }
    }
  }
  return { inline_keyboard: rows.map((row) => row.map((button) => ({ text: button.text, callback_data: button.callbackData }))) };
}

/** Short tap-payload for inline buttons: `<kind>:<id>:<action>` (kind a|c|w). */
export function telegramCallbackData(kind: "a" | "c" | "w" | "g" | "m", id: string, action: string): string {
  return `${kind}:${id}:${action}`;
}

export function parseTelegramCallback(data: string): { kind: "a" | "c" | "w" | "g" | "m"; id: string; action: string } | null {
  const match = data.match(/^([acwgm]):([^:]+):(.+)$/);
  if (!match) return null;
  return { kind: match[1] as "a" | "c" | "w" | "g" | "m", id: match[2]!, action: match[3]! };
}

/** Stops the button's loading spinner and shows a toast. Best-effort. */
export async function answerTelegramCallback(callbackQueryId: string, text?: string): Promise<void> {
  const token = getEnv("TELEGRAM_BOT_TOKEN");
  if (!token) return;
  await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ callback_query_id: callbackQueryId, text: text?.slice(0, 200) })
  }).catch(() => undefined);
}

/** Replaces a message's text (e.g. to show the decision after a tap). Best-effort. */
export async function editTelegramMessageText(chatId: string | number, messageId: number, text: string): Promise<void> {
  const token = getEnv("TELEGRAM_BOT_TOKEN");
  if (!token) return;
  await fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, message_id: messageId, text })
  }).catch(() => undefined);
}

export function redactTelegramChatId(chatId: string): string {
  const value = String(chatId);
  if (value.length <= 4) return "***";
  return `***${value.slice(-4)}`;
}

export function validateTelegramWebhookSecret(headerValue: string | null | undefined): void {
  const expected = getEnv("TELEGRAM_WEBHOOK_SECRET");
  if (!expected) return;
  if (!headerValue) {
    throw new RiskRadarError("telegram_webhook_secret_missing", "Telegram webhook secret header is required.", { header: "X-Telegram-Bot-Api-Secret-Token" }, 401);
  }
  if (headerValue !== expected) {
    throw new RiskRadarError("telegram_webhook_secret_invalid", "Telegram webhook secret header is invalid.", { header: "X-Telegram-Bot-Api-Secret-Token" }, 403);
  }
}
