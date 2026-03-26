export interface Env {
  R2_ACC1_ACCOUNT_ID: string;
  R2_ACC1_ACCESS_KEY_ID: string;
  R2_ACC1_SECRET_ACCESS_KEY: string;
  R2_ACC1_BUCKET_NAME: string;

  R2_ACC2_ACCOUNT_ID: string;
  R2_ACC2_ACCESS_KEY_ID: string;
  R2_ACC2_SECRET_ACCESS_KEY: string;
  R2_ACC2_BUCKET_NAME: string;
}

interface R2Account {
  accountId: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucketName: string;
  label: string;
}

const DOWNLOAD_LINKS_MAP: Record<string, string[]> = {
  "Account-1":[
    "https://kajarling.kajarling.ooguy.com/download",
    "https://pub-9c8bcd6f32434fe08628852555cc2e5c.r2.dev",
  ],
  "Account-2":[
    "https://lugyiappreel.carton-lugyiapp.gleeze.com/download",
    "https://pub-cbf23f7a9f914d1a88f8f1cf741716db.r2.dev",
  ],
};

const MULTIPART_THRESHOLD = 8 * 1024 * 1024;
const PART_SIZE = 10 * 1024 * 1024;
const MAX_RETRIES = 5;
const RETRY_BASE_DELAY_MS = 2000;
const INTER_ACCOUNT_DELAY_MS = 500;
const INTER_PART_DELAY_MS = 100;
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

// ============ Utility Functions ============
function encodeHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function generateUniqueFilename(extension: string): string {
  const timestamp = Date.now();
  const randomBytes = crypto.getRandomValues(new Uint8Array(8));
  const randomHex = encodeHex(randomBytes);
  return `${timestamp}_${randomHex}${extension}`;
}

function getExtension(filename: string, contentType?: string): string {
  const match = filename.match(/\.([a-zA-Z0-9]+)(\?.*)?$/);
  if (match) return `.${match[1].toLowerCase()}`;

  const mimeMap: Record<string, string> = {
    "video/mp4": ".mp4", "video/webm": ".webm", "video/x-matroska": ".mkv", "video/quicktime": ".mov", "video/x-msvideo": ".avi",
    "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp",
    "application/pdf": ".pdf", "application/zip": ".zip", "application/octet-stream": ".bin",
  };

  if (contentType) {
    const base = contentType.split(";")[0].trim().toLowerCase();
    if (mimeMap[base]) return mimeMap[base];
  }
  return ".mp4";
}

function buildDownloadLinks(filename: string, accounts: R2Account[]): string[] {
  const links: string[] =[];
  for (const account of accounts) {
    const bases = DOWNLOAD_LINKS_MAP[account.label] ||[];
    for (const base of bases) {
      links.push(`${base}/${filename}`);
    }
  }
  return links;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============ AWS Signature V4 ============
async function hmacSHA256(key: ArrayBuffer | Uint8Array, message: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
}

async function sha256(data: Uint8Array | string): Promise<string> {
  const encoded = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return encodeHex(hash);
}

async function getSignatureKey(key: string, dateStamp: string, region: string, service: string): Promise<ArrayBuffer> {
  const kDate = await hmacSHA256(new TextEncoder().encode("AWS4" + key), dateStamp);
  const kRegion = await hmacSHA256(kDate, region);
  const kService = await hmacSHA256(kRegion, service);
  return await hmacSHA256(kService, "aws4_request");
}

async function buildSignedHeaders(account: R2Account, method: string, objectKey: string, queryString: string, extraHeaders: Record<string, string>, payloadHash: string): Promise<{ url: string; headers: Record<string, string> }> {
  const endpoint = `https://${account.accountId}.r2.cloudflarestorage.com`;
  const region = "auto", service = "s3";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.substring(0, 8);
  const encodedKey = encodeURIComponent(objectKey).replace(/%2F/g, "/");
  const canonicalUri = `/${account.bucketName}/${encodedKey}`;
  const host = `${account.accountId}.r2.cloudflarestorage.com`;

  const allHeaders: Record<string, string> = { ...extraHeaders, host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate };
  const signedHeaderKeys = Object.keys(allHeaders).sort();
  const signedHeadersStr = signedHeaderKeys.join(";");
  const canonicalHeaders = signedHeaderKeys.map((k) => `${k}:${allHeaders[k]}\n`).join("");

  const canonicalRequest =[method, canonicalUri, queryString, canonicalHeaders, signedHeadersStr, payloadHash].join("\n");
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign =["AWS4-HMAC-SHA256", amzDate, credentialScope, await sha256(canonicalRequest)].join("\n");

  const signingKey = await getSignatureKey(account.secretAccessKey, dateStamp, region, service);
  const signatureBuffer = await hmacSHA256(signingKey, stringToSign);
  const signature = encodeHex(signatureBuffer);

  const authorization = `AWS4-HMAC-SHA256 Credential=${account.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;
  const fullUrl = `${endpoint}${canonicalUri}${queryString ? "?" + queryString : ""}`;

  return { url: fullUrl, headers: { ...allHeaders, Authorization: authorization } };
}

// ============ API Calls ============
async function withRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try { return await fn(); } catch (err) {
      if (attempt < MAX_RETRIES) {
        const base = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
        await delay(Math.round(base + base * 0.3 * (Math.random() * 2 - 1)));
      } else { throw err; }
    }
  }
  throw new Error("unreachable");
}

async function uploadSimplePut(account: R2Account, objectKey: string, body: Uint8Array, contentType: string): Promise<void> {
  await withRetry(`${account.label} PUT`, async () => {
    const { url, headers } = await buildSignedHeaders(account, "PUT", objectKey, "", { "content-length": body.byteLength.toString(), "content-type": contentType }, await sha256(body));
    const res = await fetch(url, { method: "PUT", headers, body });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    await res.arrayBuffer();
  });
}

async function initiateMultipart(account: R2Account, objectKey: string, contentType: string): Promise<string> {
  return await withRetry(`${account.label} InitMultipart`, async () => {
    const { url, headers } = await buildSignedHeaders(account, "POST", objectKey, "uploads=", { "content-type": contentType }, await sha256(""));
    const res = await fetch(url, { method: "POST", headers });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const xml = await res.text();
    const match = xml.match(/<UploadId>(.+?)<\/UploadId>/);
    if (!match) throw new Error("No UploadId in response");
    return match[1];
  });
}

async function uploadPart(account: R2Account, objectKey: string, uploadId: string, partNumber: number, partData: Uint8Array): Promise<string> {
  return await withRetry(`${account.label} Part#${partNumber}`, async () => {
    const { url, headers } = await buildSignedHeaders(account, "PUT", objectKey, `partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`, { "content-length": partData.byteLength.toString() }, UNSIGNED_PAYLOAD);
    const res = await fetch(url, { method: "PUT", headers, body: partData });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const etag = res.headers.get("etag") || "";
    await res.arrayBuffer();
    return etag;
  });
}

async function completeMultipart(account: R2Account, objectKey: string, uploadId: string, parts: { partNumber: number; etag: string }[]): Promise<void> {
  await withRetry(`${account.label} CompleteMultipart`, async () => {
    const xmlParts = parts.map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`).join("");
    const bodyBytes = new TextEncoder().encode(`<CompleteMultipartUpload>${xmlParts}</CompleteMultipartUpload>`);
    const { url, headers } = await buildSignedHeaders(account, "POST", objectKey, `uploadId=${encodeURIComponent(uploadId)}`, { "content-length": bodyBytes.byteLength.toString(), "content-type": "application/xml" }, await sha256(bodyBytes));
    const res = await fetch(url, { method: "POST", headers, body: bodyBytes });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    await res.arrayBuffer();
  });
}

async function abortMultipart(account: R2Account, objectKey: string, uploadId: string): Promise<void> {
  try {
    const { url, headers } = await buildSignedHeaders(account, "DELETE", objectKey, `uploadId=${encodeURIComponent(uploadId)}`, {}, await sha256(""));
    const res = await fetch(url, { method: "DELETE", headers });
    await res.arrayBuffer();
  } catch {}
}

async function streamingMultipartUpload(account: R2Account, objectKey: string, reader: ReadableStreamDefaultReader<Uint8Array>, contentType: string): Promise<{ totalSize: number; partCount: number }> {
  const uploadId = await initiateMultipart(account, objectKey, contentType);
  try {
    const parts: { partNumber: number; etag: string }[] =[];
    let partNumber = 0, totalUploaded = 0, buffer = new Uint8Array(PART_SIZE), bufferOffset = 0;

    const flushPart = async (isFinal: boolean) => {
      if (bufferOffset === 0) return;
      partNumber++;
      const etag = await uploadPart(account, objectKey, uploadId, partNumber, buffer.subarray(0, bufferOffset));
      parts.push({ partNumber, etag });
      totalUploaded += bufferOffset;
      bufferOffset = 0;
      if (!isFinal) await delay(INTER_PART_DELAY_MS);
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      let chunkOffset = 0;
      while (chunkOffset < value.byteLength) {
        const copyLen = Math.min(PART_SIZE - bufferOffset, value.byteLength - chunkOffset);
        buffer.set(value.subarray(chunkOffset, chunkOffset + copyLen), bufferOffset);
        bufferOffset += copyLen; chunkOffset += copyLen;
        if (bufferOffset >= PART_SIZE) await flushPart(false);
      }
    }
    await flushPart(true);
    if (parts.length === 0) throw new Error("No data received");
    await completeMultipart(account, objectKey, uploadId, parts);
    return { totalSize: totalUploaded, partCount: parts.length };
  } catch (err) {
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

async function bufferMultipartUpload(account: R2Account, objectKey: string, body: Uint8Array, contentType: string): Promise<void> {
  const uploadId = await initiateMultipart(account, objectKey, contentType);
  try {
    const totalParts = Math.ceil(body.byteLength / PART_SIZE);
    const parts: { partNumber: number; etag: string }[] =[];
    for (let i = 0; i < totalParts; i++) {
      const start = i * PART_SIZE;
      const etag = await uploadPart(account, objectKey, uploadId, i + 1, body.subarray(start, Math.min(start + PART_SIZE, body.byteLength)));
      parts.push({ partNumber: i + 1, etag });
      if (i < totalParts - 1) await delay(INTER_PART_DELAY_MS);
    }
    await completeMultipart(account, objectKey, uploadId, parts);
  } catch (err) {
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

async function uploadToBothR2(accounts: R2Account[], objectKey: string, body: Uint8Array, contentType: string): Promise<string[]> {
  const successes: string[] = [], errors: string[] =[];
  for (let idx = 0; idx < accounts.length; idx++) {
    const account = accounts[idx];
    try {
      if (body.byteLength > MULTIPART_THRESHOLD) await bufferMultipartUpload(account, objectKey, body, contentType);
      else await uploadSimplePut(account, objectKey, body, contentType);
      successes.push(account.label);
      if (idx < accounts.length - 1) await delay(INTER_ACCOUNT_DELAY_MS);
    } catch (err) { errors.push(`${account.label}: ${(err as Error).message}`); }
  }
  if (successes.length === 0) throw new Error(`Uploads failed: ${errors.join("; ")}`);
  return successes;
}

// ============ HTML WEB UI ============
const HTML_UI = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare R2 Multi Uploader</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; max-width: 600px; margin: 40px auto; padding: 20px; }
        h2 { text-align: center; color: #2c3e50; }
        .card { background: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        label { font-weight: bold; display: block; margin-bottom: 8px; }
        input[type="file"], input[type="text"] { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; background-color: #3498db; color: white; padding: 12px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; transition: 0.3s; }
        button:hover { background-color: #2980b9; }
        button:disabled { background-color: #95a5a6; cursor: not-allowed; }
        #status { text-align: center; margin-top: 15px; font-weight: bold; color: #e67e22; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; display: none; }
        .link-list { margin-top: 10px; padding-left: 20px; }
        .link-list li { margin-bottom: 5px; }
        .link-list a { color: #3498db; text-decoration: none; }
        .link-list a:hover { text-decoration: underline; }
    </style>
</head>
<body>

    <h2>🌩️ R2 Multi Uploader</h2>

    <div class="card">
        <label>📁 Direct File Upload</label>
        <input type="file" id="fileInput">
        <button id="btnFile" onclick="uploadFile()">Upload File</button>
    </div>

    <div class="card">
        <label>🔗 Remote URL Upload</label>
        <input type="text" id="urlInput" placeholder="https://example.com/video.mp4">
        <button id="btnUrl" onclick="uploadUrl()">Upload URL</button>
    </div>

    <div id="status"></div>
    <div id="resultBox" class="card" style="display:none;">
        <h3 style="margin-top:0; color:#27ae60;">✅ Upload Success!</h3>
        <p><strong>Filename:</strong> <span id="resName"></span></p>
        <p><strong>Size:</strong> <span id="resSize"></span> MB</p>
        <p><strong>Download Links:</strong></p>
        <ul id="resLinks" class="link-list"></ul>
    </div>

    <pre id="errorBox"></pre>

    <script>
        function setLoading(isLoading, text) {
            document.getElementById('btnFile').disabled = isLoading;
            document.getElementById('btnUrl').disabled = isLoading;
            document.getElementById('status').innerText = text;
            document.getElementById('resultBox').style.display = "none";
            document.getElementById('errorBox').style.display = "none";
        }

        function showResult(data) {
            document.getElementById('resName').innerText = data.filename;
            document.getElementById('resSize').innerText = (data.size / 1024 / 1024).toFixed(2);
            
            const ul = document.getElementById('resLinks');
            ul.innerHTML = "";
            data.links.forEach(link => {
                const li = document.createElement('li');
                li.innerHTML = \`<a href="\${link}" target="_blank">\${link}</a>\`;
                ul.appendChild(li);
            });
            document.getElementById('resultBox').style.display = "block";
        }

        function showError(err) {
            const pre = document.getElementById('errorBox');
            pre.innerText = "❌ Error:\\n" + JSON.stringify(err, null, 2);
            pre.style.display = "block";
        }

        async function uploadFile() {
            const file = document.getElementById('fileInput').files[0];
            if (!file) return alert("Please select a file to upload.");
            
            setLoading(true, "⏳ Uploading file to R2 accounts... Please wait.");
            const formData = new FormData();
            formData.append("file", file);

            try {
                const res = await fetch("/upload", { method: "POST", body: formData });
                const json = await res.json();
                if (!res.ok) throw json;
                setLoading(false, "");
                showResult(json);
            } catch (err) {
                setLoading(false, "");
                showError(err);
            }
        }

        async function uploadUrl() {
            const url = document.getElementById('urlInput').value;
            if (!url) return alert("Please enter a valid URL.");
            
            setLoading(true, "⏳ Fetching and uploading from Remote URL... Please wait.");
            try {
                const res = await fetch("/remote-upload", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url })
                });
                const json = await res.json();
                if (!res.ok) throw json;
                setLoading(false, "");
                showResult(json);
            } catch (err) {
                setLoading(false, "");
                showError(err);
            }
        }
    </script>
</body>
</html>
`;

// ============ Main Worker Entry Point ============
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Serve HTML Web UI on the root path (GET /)
    if (request.method === "GET" && url.pathname === "/") {
      return new Response(HTML_UI, {
        headers: { "Content-Type": "text/html;charset=UTF-8" }
      });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const accounts: R2Account[] =[
      { accountId: env.R2_ACC1_ACCOUNT_ID, accessKeyId: env.R2_ACC1_ACCESS_KEY_ID, secretAccessKey: env.R2_ACC1_SECRET_ACCESS_KEY, bucketName: env.R2_ACC1_BUCKET_NAME, label: "Account-1" },
      { accountId: env.R2_ACC2_ACCOUNT_ID, accessKeyId: env.R2_ACC2_ACCESS_KEY_ID, secretAccessKey: env.R2_ACC2_SECRET_ACCESS_KEY, bucketName: env.R2_ACC2_BUCKET_NAME, label: "Account-2" },
    ];

    // 1. Direct File Upload Endpoint
    if (url.pathname === "/upload") {
      try {
        const contentType = request.headers.get("content-type") || "";
        if (!contentType.includes("multipart/form-data")) throw new Error("Unsupported content type");
        const formData = await request.formData();
        const file = formData.get("file") as File | null;
        if (!file) throw new Error("No file provided");

        const ext = getExtension(file.name, file.type);
        const uniqueName = generateUniqueFilename(ext);
        const buffer = new Uint8Array(await file.arrayBuffer());
        const mime = file.type || "application/octet-stream";

        const results = await uploadToBothR2(accounts, uniqueName, buffer, mime);

        return new Response(JSON.stringify({ filename: uniqueName, size: buffer.byteLength, links: buildDownloadLinks(uniqueName, accounts), uploadedTo: results }), { headers: { "Content-Type": "application/json" } });
      } catch (err) {
        return new Response(JSON.stringify({ error: (err as Error).message }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    // 2. Remote URL Upload Endpoint (Streaming)
    if (url.pathname === "/remote-upload") {
      try {
        let remoteUrl = "";
        try {
          const body = await request.json() as { url: string };
          remoteUrl = body.url;
        } catch { throw new Error("Invalid JSON body"); }
        if (!remoteUrl) throw new Error("URL is required");

        const probeRes = await fetch(remoteUrl, { method: "HEAD", redirect: "follow", headers: { "User-Agent": "Mozilla/5.0" } });
        const remoteContentType = probeRes.headers.get("content-type") || "application/octet-stream";
        const contentLength = parseInt(probeRes.headers.get("content-length") || "0", 10);
        
        let pathName = "file";
        try { pathName = new URL(remoteUrl).pathname; } catch {}
        const uniqueName = generateUniqueFilename(getExtension(pathName, remoteContentType));

        if (contentLength > 0 && contentLength <= MULTIPART_THRESHOLD) {
          const dlRes = await fetch(remoteUrl, { redirect: "follow", headers: { "User-Agent": "Mozilla/5.0" } });
          const buffer = new Uint8Array(await dlRes.arrayBuffer());
          const results = await uploadToBothR2(accounts, uniqueName, buffer, remoteContentType);
          return new Response(JSON.stringify({ filename: uniqueName, size: buffer.byteLength, links: buildDownloadLinks(uniqueName, accounts), uploadedTo: results }), { headers: { "Content-Type": "application/json" } });
        }

        const successes: string[] = [], errors: string[] =[];
        let finalSize = 0;
        for (let idx = 0; idx < accounts.length; idx++) {
          const account = accounts[idx];
          try {
            const dlRes = await fetch(remoteUrl, { redirect: "follow", headers: { "User-Agent": "Mozilla/5.0", "Accept-Encoding": "identity" } });
            if (!dlRes.ok) throw new Error(`Download failed: ${dlRes.status}`);
            const result = await streamingMultipartUpload(account, uniqueName, dlRes.body!.getReader(), remoteContentType);
            finalSize = result.totalSize;
            successes.push(account.label);
            if (idx < accounts.length - 1) await delay(INTER_ACCOUNT_DELAY_MS);
          } catch (err) { errors.push(`${account.label}: ${(err as Error).message}`); }
        }
        if (successes.length === 0) throw new Error(`Uploads failed: ${errors.join("; ")}`);
        return new Response(JSON.stringify({ filename: uniqueName, size: finalSize, links: buildDownloadLinks(uniqueName, accounts), uploadedTo: successes }), { headers: { "Content-Type": "application/json" } });

      } catch (err) {
        return new Response(JSON.stringify({ error: (err as Error).message }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    return new Response("Not Found", { status: 404 });
  }
};
