// server-local.mjs
// FortiOS 7.4 (7.4.13) & 7.6 (7.6.8) Lokal Uygulama Sunucusu
// Özellikler:
// 1. .conf Dosyası Analizi (7.4 ve 7.6 Best Practices, NPU, ZTNA, CASB, DLP, SD-WAN, PSIRT, Yükseltme Danışmanı)
// 2. Canlı FortiGate Cihaz Bağlantısı (SSH Kullanıcı Adı/Şifre/2FA & HTTPS REST API üzerinden canlı konfigürasyon çekme)
// 3. Rapor (.PDF, .HTML) ve CLI düzeltme (.CLI.TXT) çıktılarını çalışma klasörüne otomatik kaydetme

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Client as SshClient } from "ssh2";
import workerDefault from "./_worker.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ASSET_DIR = path.join(__dirname, "PUBLIC_ASSETS");
const PORT = process.env.PORT || 8788;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".pdf": "application/pdf",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".conf": "text/plain; charset=utf-8"
};

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 50 * 1024 * 1024) {
        reject(new Error("Dosya boyutu çok büyük (Maksimum 50MB)."));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function findBrowserExecutable() {
  const candidates = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
  ];
  return candidates.find(p => fs.existsSync(p)) || null;
}

function convertHtmlFileToPdf(htmlFilePath, pdfFilePath) {
  return new Promise((resolve, reject) => {
    const browserBin = findBrowserExecutable();
    if (!browserBin) {
      reject(new Error("PDF dönüştürücü için Microsoft Edge veya Google Chrome bulunamadı."));
      return;
    }

    const fileUrl = `file:///${htmlFilePath.replace(/\\/g, "/")}`;
    const proc = spawn(browserBin, [
      "--headless",
      "--disable-gpu",
      "--no-pdf-header-footer",
      `--print-to-pdf=${pdfFilePath}`,
      fileUrl
    ]);

    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error("PDF oluşturma işlemi zaman aşımına uğradı."));
    }, 20000);

    proc.on("close", () => {
      clearTimeout(timer);
      if (fs.existsSync(pdfFilePath) && fs.statSync(pdfFilePath).size > 0) {
        resolve(pdfFilePath);
      } else {
        reject(new Error("PDF dosyası oluşturulamadı."));
      }
    });

    proc.on("error", err => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// FortiGate HTTPS REST API üzerinden canlı .conf çekme
function fetchFortiGateRestApiConfig({ host, port = 443, apiToken, vdom = "root" }) {
  return new Promise((resolve, reject) => {
    const cleanHost = String(host || "").replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim();
    const targetPort = Number(port) || 443;
    const apiPath = `/api/v2/monitor/system/config/backup?scope=global&vdom=${encodeURIComponent(vdom)}`;

    const req = https.request(
      {
        hostname: cleanHost,
        port: targetPort,
        path: apiPath,
        method: "GET",
        rejectUnauthorized: false,
        timeout: 15000,
        headers: {
          "Authorization": `Bearer ${apiToken.trim()}`,
          "Accept": "text/plain, application/json"
        }
      },
      (res) => {
        let data = "";
        res.on("data", chunk => { data += chunk; });
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300 && data.includes("config ")) {
            resolve(data);
          } else {
            reject(new Error(`FortiGate REST API yanıtı (HTTP ${res.statusCode}): Lütfen IP, Port ve REST API Token yetkilerini kontrol edin.`));
          }
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("FortiGate bağlantısı zaman aşımına uğradı (15 sn)."));
    });
    req.on("error", (err) => {
      reject(new Error(`FortiGate bağlantı hatası: ${err.message}`));
    });
    req.end();
  });
}

// FortiGate SSH üzerinden Kullanıcı Adı + Şifre (+ varsa FortiToken 2FA) ile canlı .conf çekme
function fetchFortiGateSshConfig({ host, port = 22, username = "admin", password = "", tokenCode = "", command = "show" }) {
  return new Promise((resolve, reject) => {
    const cleanHost = String(host || "").replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim();
    const targetPort = Number(port) || 22;
    const cleanUser = String(username || "admin").trim();
    const allowedCmd = command === "show full-configuration" ? "show full-configuration" : "show";

    const conn = new SshClient();
    let stdout = "";
    let settled = false;

    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { conn.end(); } catch (_) {}
      if (err) reject(err);
      else resolve(result);
    };

    const timer = setTimeout(() => {
      finish(new Error("SSH bağlantısı zaman aşımına uğradı (35 sn). IP, port ve erişim izinlerini kontrol edin."));
    }, 35000);

    conn.on("keyboard-interactive", (_name, _instructions, _lang, prompts, cb) => {
      const answers = (prompts || []).map(p => {
        const promptText = String(p.prompt || "").toLowerCase();
        if (promptText.includes("token") || promptText.includes("code") || promptText.includes("verification")) {
          return String(tokenCode || password || "");
        }
        return String(password || "");
      });
      cb(answers);
    });

    conn.on("ready", () => {
      conn.exec(allowedCmd, (err, stream) => {
        if (err) {
          finish(new Error(`SSH komut çalıştırma hatası: ${err.message}`));
          return;
        }

        stream.on("data", chunk => {
          const text = chunk.toString("utf-8");
          stdout += text;

          // FortiGate Post-Login Banner veya --More-- sayfalama çıkarsa otomatik geç
          if (text.includes("Press 'a' to accept")) {
            stream.write("a\n");
          } else if (text.includes("--More--")) {
            stream.write(" ");
          }
        });

        stream.stderr.on("data", chunk => {
          stdout += chunk.toString("utf-8");
        });

        stream.on("close", () => {
          const cleanOut = stdout.replace(/--More--\s*/g, "");
          if (cleanOut.includes("config ")) {
            finish(null, cleanOut);
          } else {
            finish(new Error("SSH bağlantısı kuruldu ancak konfigürasyon çıktısı alınamadı. Kullanıcının okuma yetkisini veya 2FA/FortiToken durumunu kontrol edin."));
          }
        });
      });
    });

    conn.on("error", err => {
      const msg = String(err.message || "");
      if (msg.toLowerCase().includes("authentication")) {
        finish(new Error("SSH kimlik doğrulama başarısız: Kullanıcı adı, şifre veya FortiToken hatalı."));
      } else {
        finish(new Error(`SSH bağlantı hatası (${cleanHost}:${targetPort}): ${msg}`));
      }
    });

    conn.connect({
      host: cleanHost,
      port: targetPort,
      username: cleanUser,
      password: String(password || ""),
      tryKeyboard: true,
      readyTimeout: 15000,
      algorithms: {
        kex: [
          "curve25519-sha256",
          "curve25519-sha256@libssh.org",
          "ecdh-sha2-nistp256",
          "ecdh-sha2-nistp384",
          "ecdh-sha2-nistp521",
          "diffie-hellman-group-exchange-sha256",
          "diffie-hellman-group14-sha256",
          "diffie-hellman-group14-sha1"
        ]
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://localhost:${PORT}`);
  const urlPath = parsedUrl.pathname;

  if (urlPath === "/_worker.js") {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("404 Not Found");
    return;
  }

  // 1. Lokal Uygulama Durumu
  if (req.method === "GET" && urlPath === "/api/local-info") {
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({
      isLocal: true,
      hasPdfEngine: Boolean(findBrowserExecutable())
    }));
    return;
  }

  // 2. Canlı FortiGate Cihazından (SSH veya REST API) Konfigürasyon Çekme
  if (req.method === "POST" && urlPath === "/api/live-device") {
    try {
      const rawBody = await readRequestBody(req);
      const payload = JSON.parse(rawBody || "{}");
      const { method, mode, host, port, apiToken, username, password, tokenCode, sshCommand, vdom } = payload;
      const connMode = method || mode || "ssh";

      if (!host) {
        res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: "Lütfen FortiGate IP adresi veya Hostname giriniz." }));
        return;
      }

      let configText = "";
      if (connMode === "ssh") {
        configText = await fetchFortiGateSshConfig({
          host,
          port: port || 22,
          username: username || "admin",
          password: password || "",
          tokenCode: tokenCode || "",
          command: sshCommand || "show"
        });
      } else {
        if (!apiToken) {
          res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ error: "FortiOS REST API bağlantısı için API Token girilmesi zorunludur." }));
          return;
        }
        configText = await fetchFortiGateRestApiConfig({ host, port: port || 443, apiToken, vdom: vdom || "root" });
      }

      const safeHost = String(host).replace(/[^a-zA-Z0-9._-]/g, "_");
      const backupFileName = `live-backup-${safeHost}-${new Date().toISOString().slice(0, 10)}.conf`;
      const backupFilePath = path.join(__dirname, backupFileName);
      fs.writeFileSync(backupFilePath, configText, "utf-8");

      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({
        ok: true,
        savedFileName: backupFileName,
        configText
      }));
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // 3. Rapor (.HTML, .PDF) ve CLI Script (.CLI.TXT) Çıktısını Klasöre Kaydetme Endpoint'i
  if (req.method === "POST" && urlPath === "/api/save-output") {
    try {
      const rawBody = await readRequestBody(req);
      const { fileName, content, generatePdf } = JSON.parse(rawBody || "{}");
      const safeName = path.basename(String(fileName || "fortios-output.txt")).replace(/[^a-zA-Z0-9._-]/g, "_");
      const targetPath = path.join(__dirname, safeName);
      fs.writeFileSync(targetPath, String(content || ""), "utf-8");

      let pdfSavedName = null;
      if (generatePdf && safeName.toLowerCase().endsWith(".html")) {
        const pdfName = safeName.replace(/\.html$/i, ".pdf");
        const pdfPath = path.join(__dirname, pdfName);
        try {
          await convertHtmlFileToPdf(targetPath, pdfPath);
          pdfSavedName = pdfName;
        } catch (_) {}
      }

      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({
        ok: true,
        savedPath: safeName,
        pdfSavedPath: pdfSavedName
      }));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // 4. Doğrudan PDF Oluşturup İndirme Endpoint'i (/api/export-pdf)
  if (req.method === "POST" && urlPath === "/api/export-pdf") {
    try {
      const rawBody = await readRequestBody(req);
      const { fileName, htmlContent } = JSON.parse(rawBody || "{}");
      const baseSlug = path.basename(String(fileName || "FortiOS-Rapor")).replace(/[^a-zA-Z0-9._-]/g, "_").replace(/\.pdf$/i, "");
      const tempHtmlPath = path.join(__dirname, `${baseSlug}.html`);
      const targetPdfPath = path.join(__dirname, `${baseSlug}.pdf`);

      fs.writeFileSync(tempHtmlPath, String(htmlContent || ""), "utf-8");
      await convertHtmlFileToPdf(tempHtmlPath, targetPdfPath);

      const pdfBuffer = fs.readFileSync(targetPdfPath);
      res.writeHead(200, {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${baseSlug}.pdf"`
      });
      res.end(pdfBuffer);
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // 5. Ana Analiz Endpoint'ini _worker.js Motoruna Yönlendir
  if (req.method === "POST" && urlPath === "/api/analyze") {
    try {
      const body = await readRequestBody(req);
      const cfRequest = new Request(`http://localhost:${PORT}${req.url}`, {
        method: req.method,
        headers: req.headers,
        body
      });
      const cfResponse = await workerDefault.fetch(cfRequest, process.env, {});
      const respBuffer = Buffer.from(await cfResponse.arrayBuffer());
      const headersObj = {};
      cfResponse.headers.forEach((v, k) => { headersObj[k] = v; });
      res.writeHead(cfResponse.status, headersObj);
      res.end(respBuffer);
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // 6. Statik Dosyaları Sun
  const cleanRel = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
  let filePath = path.join(ASSET_DIR, cleanRel);
  if (!fs.existsSync(filePath)) {
    filePath = path.join(__dirname, cleanRel);
  }

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath).toLowerCase();
    const mime = MIME_TYPES[ext] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": mime });
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("404 Not Found");
  }
});

server.listen(PORT, () => {
  console.log("================================================================================");
  console.log("FortiOS 7.4 & 7.6 Konfigürasyon Denetim, Sıkılaştırma ve Yükseltme Aracı");
  console.log(`Lokal Arayüz Adresi : http://localhost:${PORT}`);
  console.log("================================================================================");
});
