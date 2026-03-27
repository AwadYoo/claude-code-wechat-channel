#!/usr/bin/env bun
/**
 * Claude Code WeChat Channel Plugin
 *
 * Bridges WeChat messages into a Claude Code session via the Channels MCP protocol.
 * Uses the official WeChat ClawBot ilink API (same as @tencent-weixin/openclaw-weixin).
 *
 * Flow:
 *   1. QR login via ilink/bot/get_bot_qrcode + get_qrcode_status
 *   2. Long-poll ilink/bot/getupdates for incoming WeChat messages
 *   3. On each inbound message: send typing indicator via getconfig + sendtyping
 *   4. Forward messages to Claude Code as <channel> events (text, voice, image, file, video, group)
 *   5. Expose tools so Claude can reply (text) or send images back
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// ── Config ────────────────────────────────────────────────────────────────────

const CHANNEL_NAME = "wechat";
const CHANNEL_VERSION = "0.2.0";
const DEFAULT_BASE_URL = "https://ilinkai.weixin.qq.com";
const CDN_BASE_URL = "https://novac2c.cdn.weixin.qq.com/c2c";
const BOT_TYPE = "3";
const CREDENTIALS_DIR = path.join(
  process.env.HOME || "~",
  ".claude",
  "channels",
  "wechat",
);
const CREDENTIALS_FILE = path.join(CREDENTIALS_DIR, "account.json");

const LONG_POLL_TIMEOUT_MS = 35_000;
const MAX_CONSECUTIVE_FAILURES = 3;
const BACKOFF_DELAY_MS = 30_000;
const RETRY_DELAY_MS = 2_000;

// ── Logging (stderr only — stdout is MCP stdio) ─────────────────────────────

function log(msg: string) {
  process.stderr.write(`[wechat-channel] ${msg}\n`);
}

function logError(msg: string) {
  process.stderr.write(`[wechat-channel] ERROR: ${msg}\n`);
}

// ── Credentials ──────────────────────────────────────────────────────────────

type AccountData = {
  token: string;
  baseUrl: string;
  accountId: string;
  userId?: string;
  savedAt: string;
};

function loadCredentials(): AccountData | null {
  try {
    if (!fs.existsSync(CREDENTIALS_FILE)) return null;
    return JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8"));
  } catch {
    return null;
  }
}

function saveCredentials(data: AccountData): void {
  fs.mkdirSync(CREDENTIALS_DIR, { recursive: true });
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(data, null, 2), "utf-8");
  try {
    fs.chmodSync(CREDENTIALS_FILE, 0o600);
  } catch {
    // best-effort
  }
}

// ── WeChat ilink API helpers ──────────────────────────────────────────────────

function randomWechatUin(): string {
  const uint32 = crypto.randomBytes(4).readUInt32BE(0);
  return Buffer.from(String(uint32), "utf-8").toString("base64");
}

function buildHeaders(token?: string, body?: string): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    AuthorizationType: "ilink_bot_token",
    "X-WECHAT-UIN": randomWechatUin(),
  };
  if (body) {
    headers["Content-Length"] = String(Buffer.byteLength(body, "utf-8"));
  }
  if (token?.trim()) {
    headers.Authorization = `Bearer ${token.trim()}`;
  }
  return headers;
}

async function apiFetch(params: {
  baseUrl: string;
  endpoint: string;
  body: string;
  token?: string;
  timeoutMs: number;
}): Promise<string> {
  const base = params.baseUrl.endsWith("/")
    ? params.baseUrl
    : `${params.baseUrl}/`;
  const url = new URL(params.endpoint, base).toString();
  const headers = buildHeaders(params.token, params.body);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: params.body,
      signal: controller.signal,
    });
    clearTimeout(timer);
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${text}`);
    return text;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// ── AES-128-ECB crypto (for CDN media) ───────────────────────────────────────

function decryptAesEcb(data: Buffer, key: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function encryptAesEcb(data: Buffer, key: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * Parse an aes_key field (from CDNMedia) into a raw 16-byte Buffer.
 * Two encodings seen in the wild:
 *   - base64(raw 16 bytes)              → standard image media.aes_key
 *   - base64(32-char hex string)        → file/voice/video media.aes_key
 */
function parseAesKey(aesKeyBase64: string): Buffer {
  const decoded = Buffer.from(aesKeyBase64, "base64");
  if (decoded.length === 16) return decoded;
  if (decoded.length === 32 && /^[0-9a-fA-F]{32}$/.test(decoded.toString("ascii"))) {
    return Buffer.from(decoded.toString("ascii"), "hex");
  }
  throw new Error(`Invalid aes_key: decoded to ${decoded.length} bytes (expected 16 or 32-char hex)`);
}

// ── CDN media download + decrypt ─────────────────────────────────────────────

async function downloadAndDecryptMedia(
  cdnUrl: string,
  aesKeyBase64: string,
): Promise<Buffer> {
  const res = await fetch(cdnUrl, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`CDN download failed: ${res.status}`);
  const encrypted = Buffer.from(await res.arrayBuffer());
  return decryptAesEcb(encrypted, parseAesKey(aesKeyBase64));
}

/**
 * Download and decrypt an inbound media item from a message.
 * Returns the path to a temp file, or null if media is unavailable.
 */
async function downloadInboundMedia(
  item: MessageItem,
  ext: string,
): Promise<string | null> {
  let encryptQueryParam: string | undefined;
  let aesKeyBase64: string | undefined;

  if (item.type === MSG_ITEM_IMAGE && item.image_item) {
    const img = item.image_item;
    encryptQueryParam = img.media?.encrypt_query_param;
    if (!encryptQueryParam) return null;
    // aeskey (hex string from WeChat) takes priority over media.aes_key
    aesKeyBase64 = img.aeskey
      ? Buffer.from(img.aeskey, "hex").toString("base64")
      : img.media?.aes_key;
  } else if (item.type === MSG_ITEM_FILE && item.file_item) {
    encryptQueryParam = item.file_item.media?.encrypt_query_param;
    aesKeyBase64 = item.file_item.media?.aes_key;
    if (!encryptQueryParam || !aesKeyBase64) return null;
  } else if (item.type === MSG_ITEM_VIDEO && item.video_item) {
    encryptQueryParam = item.video_item.media?.encrypt_query_param;
    aesKeyBase64 = item.video_item.media?.aes_key;
    if (!encryptQueryParam || !aesKeyBase64) return null;
  } else {
    return null;
  }

  if (!encryptQueryParam) return null;

  const cdnUrl = `${CDN_BASE_URL}/download?encrypted_query_param=${encodeURIComponent(encryptQueryParam)}`;
  try {
    let data: Buffer;
    if (aesKeyBase64) {
      data = await downloadAndDecryptMedia(cdnUrl, aesKeyBase64);
    } else {
      const res = await fetch(cdnUrl, { signal: AbortSignal.timeout(30_000) });
      if (!res.ok) throw new Error(`CDN download failed: ${res.status}`);
      data = Buffer.from(await res.arrayBuffer());
    }
    const tmpPath = path.join(
      os.tmpdir(),
      `wechat-inbound-${Date.now()}-${crypto.randomBytes(4).toString("hex")}${ext}`,
    );
    fs.writeFileSync(tmpPath, data);
    return tmpPath;
  } catch (err) {
    logError(`下载入站媒体失败: ${String(err)}`);
    return null;
  }
}

// ── CDN media upload (for sending images / files) ────────────────────────────

interface UploadUrlResp {
  upload_param?: string;
  thumb_upload_param?: string;
  ret?: number;
}

async function getUploadUrl(
  baseUrl: string,
  token: string,
  toUserId: string,
  filekey: string,
  mediaType: number,
  rawsize: number,
  rawfilemd5: string,
  filesize: number,
  aeskeyHex: string,
): Promise<UploadUrlResp> {
  const raw = await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/getuploadurl",
    body: JSON.stringify({
      filekey,
      media_type: mediaType,
      to_user_id: toUserId,
      rawsize,
      rawfilemd5,
      filesize,
      no_need_thumb: true,
      aeskey: aeskeyHex,
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 10_000,
  });
  return JSON.parse(raw) as UploadUrlResp;
}

async function uploadToCdn(
  uploadParam: string,
  filekey: string,
  plaintext: Buffer,
  aesKey: Buffer,
): Promise<string> {
  const ciphertext = encryptAesEcb(plaintext, aesKey);
  const cdnUrl = `${CDN_BASE_URL}/upload?encrypted_query_param=${encodeURIComponent(uploadParam)}&filekey=${encodeURIComponent(filekey)}`;
  const res = await fetch(cdnUrl, {
    method: "POST",
    body: ciphertext,
    headers: { "Content-Type": "application/octet-stream" },
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) {
    const errMsg = res.headers.get("x-error-message") ?? `status ${res.status}`;
    throw new Error(`CDN upload failed: ${errMsg}`);
  }
  const downloadParam = res.headers.get("x-encrypted-param");
  if (!downloadParam) throw new Error("CDN upload response missing x-encrypted-param header");
  return downloadParam;
}

// ── Typing indicator ──────────────────────────────────────────────────────────

interface GetConfigResp {
  typing_ticket?: string;
  ret?: number;
}

async function getTypingTicket(
  baseUrl: string,
  token: string,
  toUserId: string,
  contextToken: string,
  ilinkUserId: string,
): Promise<string | null> {
  try {
    const raw = await apiFetch({
      baseUrl,
      endpoint: "ilink/bot/getconfig",
      body: JSON.stringify({
        to_user_id: toUserId,
        context_token: contextToken,
        ilink_user_id: ilinkUserId,
        base_info: { channel_version: CHANNEL_VERSION },
      }),
      token,
      timeoutMs: 5_000,
    });
    const resp = JSON.parse(raw) as GetConfigResp;
    return resp.typing_ticket ?? null;
  } catch {
    return null;
  }
}

async function sendTyping(
  baseUrl: string,
  token: string,
  toUserId: string,
  contextToken: string,
  typingTicket: string,
): Promise<void> {
  await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/sendtyping",
    body: JSON.stringify({
      to_user_id: toUserId,
      typing_ticket: typingTicket,
      context_token: contextToken,
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 5_000,
  });
}

/** Fire-and-forget: fetch typing_ticket then send typing indicator. */
async function showTypingIndicator(
  baseUrl: string,
  token: string,
  toUserId: string,
  contextToken: string,
  ilinkUserId: string,
): Promise<void> {
  try {
    const ticket = await getTypingTicket(baseUrl, token, toUserId, contextToken, ilinkUserId);
    if (ticket) {
      await sendTyping(baseUrl, token, toUserId, contextToken, ticket);
    }
  } catch {
    // typing indicator is best-effort; never block message processing
  }
}

// ── QR Login ─────────────────────────────────────────────────────────────────

interface QRCodeResponse {
  qrcode: string;
  qrcode_img_content: string;
}

interface QRStatusResponse {
  status: "wait" | "scaned" | "confirmed" | "expired";
  bot_token?: string;
  ilink_bot_id?: string;
  baseurl?: string;
  ilink_user_id?: string;
}

async function fetchQRCode(baseUrl: string): Promise<QRCodeResponse> {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const url = new URL(
    `ilink/bot/get_bot_qrcode?bot_type=${encodeURIComponent(BOT_TYPE)}`,
    base,
  );
  const res = await fetch(url.toString());
  if (!res.ok) throw new Error(`QR fetch failed: ${res.status}`);
  return (await res.json()) as QRCodeResponse;
}

async function pollQRStatus(
  baseUrl: string,
  qrcode: string,
): Promise<QRStatusResponse> {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const url = new URL(
    `ilink/bot/get_qrcode_status?qrcode=${encodeURIComponent(qrcode)}`,
    base,
  );
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 35_000);
  try {
    const res = await fetch(url.toString(), {
      headers: { "iLink-App-ClientVersion": "1" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`QR status failed: ${res.status}`);
    return (await res.json()) as QRStatusResponse;
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      return { status: "wait" };
    }
    throw err;
  }
}

async function doQRLogin(baseUrl: string): Promise<AccountData | null> {
  log("正在获取微信登录二维码...");
  const qrResp = await fetchQRCode(baseUrl);

  // Always log the raw URL before attempting terminal rendering.
  // Block-drawing characters from qrcode-terminal can render as garbled bytes
  // in Claude Code's interface, piped output, or non-UTF-8 environments.
  log(`\n扫码链接（可复制到浏览器或用"从相册选取"扫描）:\n${qrResp.qrcode_img_content}\n`);
  log("请使用微信扫描以下二维码：\n");
  try {
    const qrterm = await import("qrcode-terminal");
    await new Promise<void>((resolve) => {
      qrterm.default.generate(
        qrResp.qrcode_img_content,
        { small: true },
        (qr: string) => {
          process.stderr.write(qr + "\n");
          resolve();
        },
      );
    });
  } catch {
    // qrcode-terminal unavailable — URL above is sufficient
  }

  log("等待扫码...");
  const deadline = Date.now() + 480_000;
  let scannedPrinted = false;

  while (Date.now() < deadline) {
    const status = await pollQRStatus(baseUrl, qrResp.qrcode);

    switch (status.status) {
      case "wait":
        break;
      case "scaned":
        if (!scannedPrinted) {
          log("👀 已扫码，请在微信中确认...");
          scannedPrinted = true;
        }
        break;
      case "expired":
        log("二维码已过期，请重新启动。");
        return null;
      case "confirmed": {
        if (!status.ilink_bot_id || !status.bot_token) {
          logError("登录确认但未返回 bot 信息");
          return null;
        }
        const account: AccountData = {
          token: status.bot_token,
          baseUrl: status.baseurl || baseUrl,
          accountId: status.ilink_bot_id,
          userId: status.ilink_user_id,
          savedAt: new Date().toISOString(),
        };
        saveCredentials(account);
        log("✅ 微信连接成功！");
        return account;
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }

  log("登录超时");
  return null;
}

// ── WeChat Message Types ──────────────────────────────────────────────────────

const MSG_TYPE_USER = 1;
const MSG_TYPE_BOT = 2;
const MSG_STATE_FINISH = 2;

const MSG_ITEM_TEXT = 1;
const MSG_ITEM_IMAGE = 2;
const MSG_UPLOAD_IMAGE = 1; // UploadMediaType: 1=IMAGE, 2=VIDEO, 3=FILE
const MSG_UPLOAD_VIDEO = 2;
const MSG_UPLOAD_FILE = 3;
const MSG_ITEM_VOICE = 3;
const MSG_ITEM_FILE = 4;
const MSG_ITEM_VIDEO = 5;

interface TextItem {
  text?: string;
}

interface MediaRef {
  encrypt_query_param?: string;
  aes_key?: string;         // base64-encoded AES key
  encrypt_type?: number;
}

interface ImageItem {
  aeskey?: string;          // hex string (legacy WeChat format, takes priority)
  aes_key?: string;         // base64 (legacy)
  cdn_url?: string;
  width?: number;
  height?: number;
  media_id?: string;
  mid_size?: number;        // ciphertext size (outbound)
  media?: MediaRef;         // new format
}

interface VoiceItem {
  text?: string;            // server-side speech-to-text transcript
  aes_key?: string;
  cdn_url?: string;
  duration_ms?: number;
  media?: MediaRef;
}

interface FileItem {
  file_name?: string;
  file_size?: number;
  len?: string;             // plaintext size as string (outbound)
  aes_key?: string;
  cdn_url?: string;
  media_id?: string;
  media?: MediaRef;
}

interface VideoItem {
  aes_key?: string;
  cdn_url?: string;
  duration_ms?: number;
  thumb_cdn_url?: string;
  media_id?: string;
  video_size?: number;      // ciphertext size (outbound)
  media?: MediaRef;
}

interface RefMessage {
  message_item?: MessageItem;
  title?: string;
}

interface MessageItem {
  type?: number;
  text_item?: TextItem;
  image_item?: ImageItem;
  voice_item?: VoiceItem;
  file_item?: FileItem;
  video_item?: VideoItem;
  ref_msg?: RefMessage;
}

interface WeixinMessage {
  from_user_id?: string;
  to_user_id?: string;
  client_id?: string;
  session_id?: string;
  group_id?: string;       // present for group chat messages
  message_type?: number;
  message_state?: number;
  item_list?: MessageItem[];
  context_token?: string;
  create_time_ms?: number;
}

interface GetUpdatesResp {
  ret?: number;
  errcode?: number;
  errmsg?: string;
  msgs?: WeixinMessage[];
  get_updates_buf?: string;
  longpolling_timeout_ms?: number;
}

// ── Message content extraction ────────────────────────────────────────────────

type ExtractedContent = {
  text: string;
  msgType: "text" | "voice" | "image" | "file" | "video" | "unknown";
  mediaItem?: ImageItem | FileItem | VideoItem;
  rawItem?: MessageItem;  // kept for inbound media download
};

function extractContent(msg: WeixinMessage): ExtractedContent | null {
  if (!msg.item_list?.length) return null;

  for (const item of msg.item_list) {
    switch (item.type) {
      case MSG_ITEM_TEXT: {
        if (!item.text_item?.text) continue;
        let text = item.text_item.text;
        if (item.ref_msg?.title) {
          text = `[引用: ${item.ref_msg.title}]\n${text}`;
        }
        return { text, msgType: "text" };
      }

      case MSG_ITEM_VOICE: {
        // Always prefer the server-provided transcript; fall back to placeholder
        const transcript = item.voice_item?.text;
        if (transcript) {
          return { text: `[语音转文字] ${transcript}`, msgType: "voice" };
        }
        return { text: "[语音消息（无文字转录）]", msgType: "voice" };
      }

      case MSG_ITEM_IMAGE: {
        const img = item.image_item;
        const dims = img?.width && img?.height
          ? ` (${img.width}×${img.height})`
          : "";
        return {
          text: `[图片${dims}]`,
          msgType: "image",
          mediaItem: img,
          rawItem: item,
        };
      }

      case MSG_ITEM_FILE: {
        const f = item.file_item;
        const name = f?.file_name ? ` "${f.file_name}"` : "";
        const size = f?.file_size
          ? ` (${(f.file_size / 1024).toFixed(1)} KB)`
          : "";
        return {
          text: `[文件${name}${size}]`,
          msgType: "file",
          mediaItem: f,
          rawItem: item,
        };
      }

      case MSG_ITEM_VIDEO: {
        const v = item.video_item;
        const dur = v?.duration_ms
          ? ` (${(v.duration_ms / 1000).toFixed(1)}s)`
          : "";
        return {
          text: `[视频${dur}]`,
          msgType: "video",
          mediaItem: v,
          rawItem: item,
        };
      }

      default:
        return { text: `[未知消息类型 ${item.type}]`, msgType: "unknown" };
    }
  }
  return null;
}

// ── Context token cache (persisted to disk across session restarts) ───────────
// Key: senderId (DM) or groupId (group chat)

const CONTEXT_TOKEN_FILE = path.join(CREDENTIALS_DIR, "context_tokens.json");

const contextTokenCache = new Map<string, string>(
  (() => {
    try {
      const raw = fs.readFileSync(CONTEXT_TOKEN_FILE, "utf-8");
      return Object.entries(JSON.parse(raw)) as [string, string][];
    } catch {
      return [];
    }
  })(),
);

function cacheContextToken(key: string, token: string): void {
  contextTokenCache.set(key, token);
  // Persist to disk so the token survives Claude Code session restarts
  try {
    fs.mkdirSync(CREDENTIALS_DIR, { recursive: true });
    fs.writeFileSync(
      CONTEXT_TOKEN_FILE,
      JSON.stringify(Object.fromEntries(contextTokenCache), null, 2),
      "utf-8",
    );
  } catch { /* best-effort */ }
}

function getCachedContextToken(key: string): string | undefined {
  return contextTokenCache.get(key);
}

// ── Typing indicator keep-alive ───────────────────────────────────────────────
// Key: senderId (or groupId). Cleared when a reply tool is called.

const typingIntervals = new Map<string, ReturnType<typeof setInterval>>();
const TYPING_REFRESH_MS = 4_000;

function startTypingKeepAlive(
  baseUrl: string,
  token: string,
  senderId: string,
  contextToken: string,
  ilinkUserId: string,
): void {
  stopTypingKeepAlive(senderId);
  showTypingIndicator(baseUrl, token, senderId, contextToken, ilinkUserId).catch(() => {});
  const interval = setInterval(() => {
    showTypingIndicator(baseUrl, token, senderId, contextToken, ilinkUserId).catch(() => {});
  }, TYPING_REFRESH_MS);
  typingIntervals.set(senderId, interval);
}

function stopTypingKeepAlive(senderId: string): void {
  const interval = typingIntervals.get(senderId);
  if (interval !== undefined) {
    clearInterval(interval);
    typingIntervals.delete(senderId);
  }
}

// ── getUpdates / sendMessage ──────────────────────────────────────────────────

async function getUpdates(
  baseUrl: string,
  token: string,
  getUpdatesBuf: string,
): Promise<GetUpdatesResp> {
  try {
    const raw = await apiFetch({
      baseUrl,
      endpoint: "ilink/bot/getupdates",
      body: JSON.stringify({
        get_updates_buf: getUpdatesBuf,
        base_info: { channel_version: CHANNEL_VERSION },
      }),
      token,
      timeoutMs: LONG_POLL_TIMEOUT_MS,
    });
    return JSON.parse(raw) as GetUpdatesResp;
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      return { ret: 0, msgs: [], get_updates_buf: getUpdatesBuf };
    }
    throw err;
  }
}

function generateClientId(): string {
  return `claude-code-wechat:${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

async function sendTextMessage(
  baseUrl: string,
  token: string,
  to: string,
  text: string,
  contextToken: string,
): Promise<void> {
  await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/sendmessage",
    body: JSON.stringify({
      msg: {
        from_user_id: "",
        to_user_id: to,
        client_id: generateClientId(),
        message_type: MSG_TYPE_BOT,
        message_state: MSG_STATE_FINISH,
        item_list: [{ type: MSG_ITEM_TEXT, text_item: { text } }],
        context_token: contextToken,
      },
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 15_000,
  });
}

async function sendImageMessage(
  baseUrl: string,
  token: string,
  to: string,
  imageBuffer: Buffer,
  contextToken: string,
): Promise<void> {
  const aesKey = crypto.randomBytes(16);
  const filekey = crypto.randomBytes(16).toString("hex");
  const rawsize = imageBuffer.length;
  const rawfilemd5 = crypto.createHash("md5").update(imageBuffer).digest("hex");
  // AES-128-ECB padded size
  const filesize = Math.ceil((rawsize + 1) / 16) * 16;
  const aeskeyHex = aesKey.toString("hex");

  // Get CDN upload param
  const uploadResp = await getUploadUrl(
    baseUrl, token, to,
    filekey, MSG_UPLOAD_IMAGE,
    rawsize, rawfilemd5, filesize, aeskeyHex,
  );
  if (!uploadResp.upload_param) {
    throw new Error(`getuploadurl failed: ${JSON.stringify(uploadResp)}`);
  }

  // Upload to CDN, get download param from response header
  const downloadParam = await uploadToCdn(
    uploadResp.upload_param, filekey, imageBuffer, aesKey,
  );

  // Send image message with CDN reference
  await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/sendmessage",
    body: JSON.stringify({
      msg: {
        from_user_id: "",
        to_user_id: to,
        client_id: generateClientId(),
        message_type: MSG_TYPE_BOT,
        message_state: MSG_STATE_FINISH,
        item_list: [{
          type: MSG_ITEM_IMAGE,
          image_item: {
            media: {
              encrypt_query_param: downloadParam,
              aes_key: Buffer.from(aeskeyHex).toString("base64"),
              encrypt_type: 1,
            },
            mid_size: filesize,
          },
        }],
        context_token: contextToken,
      },
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 15_000,
  });
}

async function sendFileMessage(
  baseUrl: string,
  token: string,
  to: string,
  fileBuffer: Buffer,
  fileName: string,
  contextToken: string,
): Promise<void> {
  const aesKey = crypto.randomBytes(16);
  const filekey = crypto.randomBytes(16).toString("hex");
  const rawsize = fileBuffer.length;
  const rawfilemd5 = crypto.createHash("md5").update(fileBuffer).digest("hex");
  const filesize = Math.ceil((rawsize + 1) / 16) * 16;
  const aeskeyHex = aesKey.toString("hex");

  const uploadResp = await getUploadUrl(
    baseUrl, token, to,
    filekey, MSG_UPLOAD_FILE,
    rawsize, rawfilemd5, filesize, aeskeyHex,
  );
  if (!uploadResp.upload_param) {
    throw new Error(`getuploadurl failed: ${JSON.stringify(uploadResp)}`);
  }

  const downloadParam = await uploadToCdn(
    uploadResp.upload_param, filekey, fileBuffer, aesKey,
  );

  await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/sendmessage",
    body: JSON.stringify({
      msg: {
        from_user_id: "",
        to_user_id: to,
        client_id: generateClientId(),
        message_type: MSG_TYPE_BOT,
        message_state: MSG_STATE_FINISH,
        item_list: [{
          type: MSG_ITEM_FILE,
          file_item: {
            media: {
              encrypt_query_param: downloadParam,
              aes_key: Buffer.from(aeskeyHex).toString("base64"),
              encrypt_type: 1,
            },
            file_name: fileName,
            len: String(rawsize),
          },
        }],
        context_token: contextToken,
      },
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 30_000,
  });
}

async function sendVideoMessage(
  baseUrl: string,
  token: string,
  to: string,
  videoBuffer: Buffer,
  contextToken: string,
): Promise<void> {
  const aesKey = crypto.randomBytes(16);
  const filekey = crypto.randomBytes(16).toString("hex");
  const rawsize = videoBuffer.length;
  const rawfilemd5 = crypto.createHash("md5").update(videoBuffer).digest("hex");
  const filesize = Math.ceil((rawsize + 1) / 16) * 16;
  const aeskeyHex = aesKey.toString("hex");

  const uploadResp = await getUploadUrl(
    baseUrl, token, to,
    filekey, MSG_UPLOAD_VIDEO,
    rawsize, rawfilemd5, filesize, aeskeyHex,
  );
  if (!uploadResp.upload_param) {
    throw new Error(`getuploadurl failed: ${JSON.stringify(uploadResp)}`);
  }

  const downloadParam = await uploadToCdn(
    uploadResp.upload_param, filekey, videoBuffer, aesKey,
  );

  await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/sendmessage",
    body: JSON.stringify({
      msg: {
        from_user_id: "",
        to_user_id: to,
        client_id: generateClientId(),
        message_type: MSG_TYPE_BOT,
        message_state: MSG_STATE_FINISH,
        item_list: [{
          type: MSG_ITEM_VIDEO,
          video_item: {
            media: {
              encrypt_query_param: downloadParam,
              aes_key: Buffer.from(aeskeyHex).toString("base64"),
              encrypt_type: 1,
            },
            video_size: filesize,
          },
        }],
        context_token: contextToken,
      },
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 120_000,
  });
}

// ── MCP Channel Server ────────────────────────────────────────────────────────

const mcp = new Server(
  { name: CHANNEL_NAME, version: CHANNEL_VERSION },
  {
    capabilities: {
      experimental: { "claude/channel": {} },
      tools: {},
    },
    instructions: [
      "Messages from WeChat users arrive as <channel source=\"wechat\" ...> tags.",
      "",
      "Tag attributes:",
      "  sender       — display name (xxx part of xxx@im.wechat)",
      "  sender_id    — full user ID (xxx@im.wechat) — REQUIRED for all reply tools",
      "  msg_type     — text | voice | image | file | video | unknown",
      "  can_reply    — 'true': reply normally; 'false': no session token, tell the user to send another message",
      "  is_group     — 'true' if from a group chat",
      "  group_id     — group ID when is_group=true (use this as the reply target in groups)",
      "  image_path   — absolute path to downloaded image temp file (present when msg_type=image)",
      "  file_path    — absolute path to downloaded file temp file (present when msg_type=file)",
      "  video_path   — absolute path to downloaded video temp file (present when msg_type=video)",
      "",
      "Tools available:",
      "  wechat_reply        — send a plain-text reply (always available)",
      "  wechat_send_image   — send an image file from local disk (provide absolute path)",
      "  wechat_send_file    — send any file (Word/PDF/Excel/etc.) from local disk",
      "  wechat_send_video   — send a video file from local disk",
      "",
      "Rules:",
      "  - If can_reply=false, do NOT call wechat_reply. Instead output: 'NOTICE: cannot reply, session token missing. User must send one more message.'",
      "  - Otherwise always use one of the reply tools — never leave a message unanswered.",
      "  - In group chats (is_group=true), pass the group_id as sender_id to reply to the group.",
      "  - Strip all markdown — WeChat renders plain text only.",
      "  - Keep replies concise. WeChat is a chat app.",
      "  - Default language is Chinese unless the user writes in another language.",
      "  - For voice messages the transcript is already in the content — treat it as text.",
      "  - When image_path/file_path/video_path is present, use the Read tool to view/analyze the file before replying.",
    ].join("\n"),
  },
);

// ── Tool handlers ─────────────────────────────────────────────────────────────

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "wechat_reply",
      description: "Send a plain-text reply to the WeChat user (or group)",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: {
            type: "string",
            description:
              "sender_id from the inbound tag (xxx@im.wechat). " +
              "In group chats use group_id instead.",
          },
          text: {
            type: "string",
            description: "Plain-text message (no markdown, no emoji unless asked)",
          },
        },
        required: ["sender_id", "text"],
      },
    },
    {
      name: "wechat_send_image",
      description: "Send a local image file to the WeChat user",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: {
            type: "string",
            description: "Same as wechat_reply sender_id",
          },
          file_path: {
            type: "string",
            description: "Absolute path to the image file on disk (PNG, JPG, etc.)",
          },
        },
        required: ["sender_id", "file_path"],
      },
    },
    {
      name: "wechat_send_file",
      description: "Send a local file (Word, PDF, Excel, etc.) to the WeChat user",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: {
            type: "string",
            description: "Same as wechat_reply sender_id",
          },
          file_path: {
            type: "string",
            description: "Absolute path to the file on disk",
          },
          file_name: {
            type: "string",
            description: "File name shown to the recipient (defaults to basename of file_path)",
          },
        },
        required: ["sender_id", "file_path"],
      },
    },
    {
      name: "wechat_send_video",
      description: "Send a local video file to the WeChat user",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: {
            type: "string",
            description: "Same as wechat_reply sender_id",
          },
          file_path: {
            type: "string",
            description: "Absolute path to the video file on disk (MP4, etc.)",
          },
        },
        required: ["sender_id", "file_path"],
      },
    },
  ],
}));

let activeAccount: AccountData | null = null;

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (!activeAccount) {
    return { content: [{ type: "text" as const, text: "error: not logged in" }] };
  }

  if (req.params.name === "wechat_reply") {
    const { sender_id, text } = req.params.arguments as {
      sender_id: string;
      text: string;
    };
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) {
      return {
        content: [{
          type: "text" as const,
          text: `error: no context_token for ${sender_id}. The user must send a message first.`,
        }],
      };
    }
    try {
      await sendTextMessage(activeAccount.baseUrl, activeAccount.token, sender_id, text, contextToken);
      stopTypingKeepAlive(sender_id);
      return { content: [{ type: "text" as const, text: "sent" }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `send failed: ${String(err)}` }] };
    }
  }

  if (req.params.name === "wechat_send_image") {
    const { sender_id, file_path } = req.params.arguments as {
      sender_id: string;
      file_path: string;
    };
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) {
      return {
        content: [{
          type: "text" as const,
          text: `error: no context_token for ${sender_id}.`,
        }],
      };
    }
    try {
      const imageBuffer = fs.readFileSync(file_path);
      await sendImageMessage(
        activeAccount.baseUrl, activeAccount.token,
        sender_id, imageBuffer, contextToken,
      );
      stopTypingKeepAlive(sender_id);
      return { content: [{ type: "text" as const, text: "image sent" }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `image send failed: ${String(err)}` }] };
    }
  }

  if (req.params.name === "wechat_send_file") {
    const { sender_id, file_path, file_name } = req.params.arguments as {
      sender_id: string;
      file_path: string;
      file_name?: string;
    };
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) {
      return {
        content: [{
          type: "text" as const,
          text: `error: no context_token for ${sender_id}.`,
        }],
      };
    }
    try {
      const fileBuffer = fs.readFileSync(file_path);
      const resolvedName = file_name || path.basename(file_path);
      await sendFileMessage(
        activeAccount.baseUrl, activeAccount.token,
        sender_id, fileBuffer, resolvedName, contextToken,
      );
      stopTypingKeepAlive(sender_id);
      return { content: [{ type: "text" as const, text: `file sent: ${resolvedName}` }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `file send failed: ${String(err)}` }] };
    }
  }

  if (req.params.name === "wechat_send_video") {
    const { sender_id, file_path } = req.params.arguments as {
      sender_id: string;
      file_path: string;
    };
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) {
      return {
        content: [{
          type: "text" as const,
          text: `error: no context_token for ${sender_id}.`,
        }],
      };
    }
    try {
      const videoBuffer = fs.readFileSync(file_path);
      await sendVideoMessage(
        activeAccount.baseUrl, activeAccount.token,
        sender_id, videoBuffer, contextToken,
      );
      stopTypingKeepAlive(sender_id);
      return { content: [{ type: "text" as const, text: "video sent" }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `video send failed: ${String(err)}` }] };
    }
  }

  throw new Error(`unknown tool: ${req.params.name}`);
});

// ── Long-poll loop ────────────────────────────────────────────────────────────

async function startPolling(account: AccountData): Promise<never> {
  const { baseUrl, token } = account;
  let getUpdatesBuf = "";
  let consecutiveFailures = 0;

  const syncBufFile = path.join(CREDENTIALS_DIR, "sync_buf.txt");
  try {
    if (fs.existsSync(syncBufFile)) {
      getUpdatesBuf = fs.readFileSync(syncBufFile, "utf-8");
      log(`恢复上次同步状态 (${getUpdatesBuf.length} bytes)`);
    }
  } catch { /* ignore */ }

  log("开始监听微信消息...");

  while (true) {
    try {
      const resp = await getUpdates(baseUrl, token, getUpdatesBuf);

      const isError =
        (resp.ret !== undefined && resp.ret !== 0) ||
        (resp.errcode !== undefined && resp.errcode !== 0);
      if (isError) {
        consecutiveFailures++;
        logError(`getUpdates 失败: ret=${resp.ret} errcode=${resp.errcode} errmsg=${resp.errmsg ?? ""}`);
        if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
          logError(`连续失败 ${MAX_CONSECUTIVE_FAILURES} 次，等待 ${BACKOFF_DELAY_MS / 1000}s`);
          consecutiveFailures = 0;
          await new Promise((r) => setTimeout(r, BACKOFF_DELAY_MS));
        } else {
          await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
        }
        continue;
      }

      consecutiveFailures = 0;

      if (resp.get_updates_buf) {
        getUpdatesBuf = resp.get_updates_buf;
        try { fs.writeFileSync(syncBufFile, getUpdatesBuf, "utf-8"); } catch { /* ignore */ }
      }

      for (const msg of resp.msgs ?? []) {
        // Log raw message for debugging (truncated context_token)
        const debugMsg = { ...msg, context_token: msg.context_token ? msg.context_token.slice(0, 20) + "…" : undefined };
        log(`RAW msg: ${JSON.stringify(debugMsg)}`);

        if (msg.message_type !== MSG_TYPE_USER) continue;

        const extracted = extractContent(msg);
        if (!extracted) continue;

        // Use || (not ??) so empty strings also fall through to the default
        const senderId = msg.from_user_id || msg.to_user_id || "unknown";
        const groupId = msg.group_id || undefined;
        const isGroup = Boolean(groupId);

        // Cache context token: group messages key by group_id, DMs by sender_id
        const contextKey = groupId || senderId;
        if (msg.context_token) {
          cacheContextToken(contextKey, msg.context_token);
          // In group chats also cache by sender_id so Claude can refer back
          if (isGroup) cacheContextToken(senderId, msg.context_token);
        } else {
          logError(`消息缺少 context_token: from=${senderId} — 无法回复，等待下一条消息`);
        }

        // Determine whether we can reply (need a context_token, either fresh or cached)
        const canReply = Boolean(getCachedContextToken(contextKey));

        const senderShort = senderId.split("@")[0] || senderId;
        log(`收到${isGroup ? "群" : "私"}消息 [${extracted.msgType}]: from=${senderShort}${isGroup ? ` group=${groupId}` : ""} can_reply=${canReply} "${extracted.text.slice(0, 60)}"`);

        // Start typing keep-alive: refreshes every 4s until a reply tool is called
        if (canReply && msg.context_token) {
          startTypingKeepAlive(baseUrl, token, senderId, msg.context_token, activeAccount!.accountId);
        }

        // Build meta for the <channel> tag
        const meta: Record<string, string> = {
          sender: senderShort,
          sender_id: isGroup ? (groupId as string) : senderId,
          msg_type: extracted.msgType,
          can_reply: String(canReply),
        };
        if (isGroup) {
          meta.is_group = "true";
          meta.group_id = groupId as string;
          meta.from_sender_id = senderId;
        }

        // Download inbound media (image/file/video) so Claude can read it
        if (extracted.rawItem) {
          const ext = extracted.msgType === "image" ? ".jpg"
            : extracted.msgType === "video" ? ".mp4"
            : extracted.msgType === "file"
              ? (path.extname((extracted.mediaItem as FileItem)?.file_name ?? "") || ".bin")
              : "";
          if (ext) {
            const mediaPath = await downloadInboundMedia(extracted.rawItem, ext);
            if (mediaPath) {
              if (extracted.msgType === "image") meta.image_path = mediaPath;
              else if (extracted.msgType === "file") meta.file_path = mediaPath;
              else if (extracted.msgType === "video") meta.video_path = mediaPath;
              log(`入站媒体已下载: ${mediaPath}`);
            }
          }
        }

        await mcp.notification({
          method: "notifications/claude/channel",
          params: { content: extracted.text, meta },
        });
      }
    } catch (err) {
      consecutiveFailures++;
      logError(`轮询异常: ${String(err)}`);
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        consecutiveFailures = 0;
        await new Promise((r) => setTimeout(r, BACKOFF_DELAY_MS));
      } else {
        await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
      }
    }
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  await mcp.connect(new StdioServerTransport());
  log("MCP 连接就绪");

  let account = loadCredentials();

  if (!account) {
    log("未找到已保存的凭据，启动微信扫码登录...");
    account = await doQRLogin(DEFAULT_BASE_URL);
    if (!account) {
      logError("登录失败，退出。");
      process.exit(1);
    }
  } else {
    log(`使用已保存账号: ${account.accountId}`);
  }

  activeAccount = account;
  await startPolling(account);
}

main().catch((err) => {
  logError(`Fatal: ${String(err)}`);
  process.exit(1);
});
