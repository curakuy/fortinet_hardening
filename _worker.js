// _worker.js
// yukaruc.tech // SW-02 FortiOS 7.4 (7.4.13) & 7.6 (7.6.8) Hardening, Vulnerability, NPU & Architecture Analyzer
// Hem Cloudflare Edge Worker üzerinde hem de lokal Node.js sunucusunda (server-local.mjs) çalışır.

const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de",
  "hotmail.com", "hotmail.co.uk", "outlook.com", "outlook.com.tr", "live.com", "msn.com",
  "icloud.com", "me.com", "mac.com", "aol.com", "protonmail.com", "proton.me",
  "yandex.com", "yandex.ru", "yandex.com.tr", "mail.com", "Mail.ru", "mail.ru",
  "gmx.com", "gmx.de", "zoho.com", "tutanota.com", "tuta.io", "fastmail.com",
  "10minutemail.com", "tempmail.com", "guerrillamail.com", "yopmail.com",
  "mailinator.com", "sharklasers.com", "trashmail.com", "getnada.com", "dispostable.com"
]);

function validateCorporateEmail(email) {
  if (!email || typeof email !== "string") {
    return { valid: false, reason: "Raporu indirmek için şirket e-posta adresinizi girmeniz zorunludur." };
  }
  const cleaned = email.trim().toLowerCase();
  const emailRegex = /^[a-z0-9._%+-]+@([a-z0-9-]+\.)+[a-z]{2,}$/;
  if (!emailRegex.test(cleaned)) {
    return { valid: false, reason: "Lütfen geçerli bir kurumsal e-posta adresi giriniz (Örn: ad.soyad@sirketiniz.com.tr)." };
  }
  const domain = cleaned.split("@")[1];
  if (FREE_EMAIL_DOMAINS.has(domain)) {
    return {
      valid: false,
      reason: `"${domain}" kişisel bir e-posta sağlayıcısıdır. Raporu indirmek için lütfen kurumsal şirket e-posta adresinizi giriniz.`
    };
  }
  return { valid: true, email: cleaned, domain };
}

// Derinlik (depth) duyarlı FortiOS config blok ayrıştırıcı
function parseConfigSection(confText, sectionHeader) {
  if (!confText) return "";
  const target = `config ${sectionHeader.trim().toLowerCase()}`;
  const lines = confText.split(/\r?\n/);
  const collected = [];
  let inTarget = false;
  let depth = 0;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    const lower = trimmed.toLowerCase();

    if (!inTarget) {
      if (lower === target) {
        inTarget = true;
        depth = 1;
      }
    } else {
      if (lower.startsWith("config ") && lower !== "config global" && lower !== "config vdom") {
        depth++;
        collected.push(rawLine);
      } else if (lower === "end") {
        depth--;
        if (depth === 0) {
          inTarget = false;
        } else {
          collected.push(rawLine);
        }
      } else {
        collected.push(rawLine);
      }
    }
  }
  return collected.join("\n");
}

function parseEditBlocks(sectionContent) {
  const blocks = [];
  if (!sectionContent) return blocks;
  const lines = sectionContent.split(/\r?\n/);
  let currentBlock = null;
  let depth = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    if (line.startsWith("config ")) {
      depth++;
      if (currentBlock) currentBlock.lines.push(line);
      continue;
    }
    if (line === "end" && depth > 0) {
      depth--;
      if (currentBlock) currentBlock.lines.push(line);
      continue;
    }
    if (depth === 0 && line.startsWith("edit ")) {
      const name = line.slice(5).replace(/^"|"$/g, "").trim();
      currentBlock = { id: name, settings: {}, lines: [], rawSub: "" };
      blocks.push(currentBlock);
    } else if (depth === 0 && line === "next") {
      currentBlock = null;
    } else if (currentBlock) {
      currentBlock.lines.push(line);
      if (depth === 0 && line.startsWith("set ")) {
        const parts = line.slice(4).trim().split(/\s+/);
        const key = parts[0];
        const val = parts.slice(1).join(" ").replace(/^"|"$/g, "");
        currentBlock.settings[key] = val;
      }
    }
  }
  return blocks;
}

function parseKeyValues(sectionContent) {
  const settings = {};
  if (!sectionContent) return settings;
  const lines = sectionContent.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.startsWith("set ")) {
      const parts = line.slice(4).trim().split(/\s+/);
      const key = parts[0];
      const val = parts.slice(1).join(" ").replace(/^"|"$/g, "");
      settings[key] = val;
    }
  }
  return settings;
}

function isVersionLessThan(verA, verB) {
  const a = String(verA).split(".").map(n => parseInt(n, 10) || 0);
  const b = String(verB).split(".").map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0;
    const y = b[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

export function analyzeFortiGateConfig(confText, targetProfile = "auto") {
  const findings = [];
  const passedControls = [];

  const headerMatch = confText.match(/^#config-version=([A-Za-z0-9_.-]+)-([\d.]+)-FW-build(\d+)/m);
  const model = headerMatch ? headerMatch[1] : "FortiGate";
  const version = headerMatch ? headerMatch[2] : (targetProfile === "7.6" ? "7.6.0" : "7.4.0");
  const build = headerMatch ? headerMatch[3] : "Bilinmiyor";
  const vdomEnabled = /opmode=\d+:vdom=1/m.test(confText) || /set\s+vdom-mode\s+multi-vdom/i.test(confText);

  const is76Branch = targetProfile === "7.6" || version.startsWith("7.6.");
  const is2GbModel = /^(FGT?|FGR)-?(40F|60F|61F|50G)/i.test(model);
  const isSslRemovedModel76 = /^(FGT?|FGR)-?(40F|60F|61F|50G|70G|90G|91G)/i.test(model);

  const sysGlobalRaw = parseConfigSection(confText, "system global");
  const sysGlobal = parseKeyValues(sysGlobalRaw);
  const hostname = sysGlobal["hostname"] || "FortiGate-Host";

  // Yardımcı: statusType = "MISSING" (Yok - Ekleme Adımları) | "MISCONFIGURED" (Var ama Hatalı - Düzeltme Adımları)
  const addFinding = (finding) => {
    const statusType = finding.statusType || "MISCONFIGURED";
    const actionLabel = statusType === "MISSING"
      ? "➕ EKSİK KONFİGÜRASYON — EKLEME ADIMLARI"
      : "🔧 HATALI / ZAYIF AYAR — DÜZELTME ADIMLARI";
    findings.push({
      id: finding.code || `FGT-${String(findings.length + 1).padStart(3, "0")}`,
      statusType,
      actionLabel,
      currentConfig: finding.currentConfig || "# Mevcut konfigürasyonda bu ayar tanımlanmamış (Varsayılan / Eksik)",
      expectedConfig: finding.expectedConfig || finding.remediation,
      docSource: finding.docSource || finding.reference,
      ...finding
    });
  };

  const addPassed = (code, category, title) => {
    passedControls.push({ id: code, category, title });
  };

  // ============================================================================
  // 1. PSIRT & FIRMWARE CVE DENETİMİ (7.4.13 & 7.6.8)
  // ============================================================================
  if (headerMatch) {
    if (version.startsWith("7.6.") && isVersionLessThan(version, "7.6.8")) {
      const cveList = [];
      if (isVersionLessThan(version, "7.6.4")) cveList.push("CVE-2025-54821 (Trusted Host CLI Bypass)");
      if (isVersionLessThan(version, "7.6.5")) cveList.push("CVE-2025-61624 (CLI Path Traversal)", "CVE-2026-22153 (fnbamd LDAP Auth Bypass)");
      if (isVersionLessThan(version, "7.6.7")) cveList.push("CVE-2026-23573 (GUI XSS)");
      cveList.push("Ekim 2026 FortiOS 7.6.8 Güvenlik Sıkılaştırma Yamaları (Bug 1328306 Local-In Virtual Patch HA-MGMT Fix)");

      addFinding({
        code: "FGT-CVE-01",
        category: "PSIRT & Firmware Zaafiyetleri (7.4 / 7.6)",
        severity: isVersionLessThan(version, "7.6.5") ? "CRITICAL" : "HIGH",
        statusType: "MISCONFIGURED",
        title: `FortiOS v${version} (7.6 Dalı) Güncel Değil — FortiOS 7.6.8 Sürümüne Yükseltilmeli`,
        description: `Cihazınız FortiOS ${version} (Build ${build}) çalıştırıyor. FortiOS 7.6.8 altında bulunan sürümler şu PSIRT zafiyetlerinden ve hata kayıtlarından etkilenmektedir: ${cveList.join(", ")}.`,
        currentConfig: `#config-version=${model}-${version}-FW-build${build}`,
        expectedConfig: `#config-version=${model}-7.6.8-FW-build3699 (Güncel FortiOS 7.6.8 Yaması)`,
        remediation: `# [DÜZELTME ADIMLARI - FIRMWARE YÜKSELTME & GEÇİCİ KORUMA]\nexecute backup config flash "pre_768_upgrade"\n# Otomatik yama zamanlayıcısını aktif edin:\nconfig system fortiguard\n    set auto-firmware-upgrade enable\n    set auto-firmware-upgrade-day sunday\n    set auto-firmware-upgrade-start-hour 2\n    set auto-firmware-upgrade-end-hour 4\nend`,
        diagnosticCli: `get system status\ndiagnose autoupdate versions\ndiagnose debug config-error-log read`,
        reference: "Fortinet Resmi Dokümanı (7.6): fortios-v7.6.8-release-notes.pdf & Fortinet PSIRT 2025/2026"
      });
    } else if (version.startsWith("7.4.") && isVersionLessThan(version, "7.4.13")) {
      const isCrit74 = isVersionLessThan(version, "7.4.7");
      addFinding({
        code: "FGT-CVE-01",
        category: "PSIRT & Firmware Zaafiyetleri (7.4 / 7.6)",
        severity: isCrit74 ? "CRITICAL" : "HIGH",
        statusType: "MISCONFIGURED",
        title: `FortiOS v${version} Sürümünde Bilinen PSIRT Zaafiyetleri — FortiOS 7.4.13 veya 7.6.8 Önerilir`,
        description: `Yüklenen konfigürasyon FortiOS ${version} (Build ${build}) sürümüne aittir. FortiOS 7.4.13 altındaki sürümler; ${isCrit74 ? "CVE-2024-55591 (Node.js websocket super_admin auth bypass), CVE-2024-21762 (SSL-VPN RCE), CVE-2024-23113 (fgfmd RCE), " : ""}CVE-2025-61624 (CLI Path Traversal) ve CVE-2025-54821 (Trusted Host Bypass) zafiyetlerinden etkilenmektedir.`,
        currentConfig: `#config-version=${model}-${version}-FW-build${build}`,
        expectedConfig: `#config-version=${model}-7.4.13 (veya FortiOS 7.6.8)`,
        remediation: `# [DÜZELTME ADIMLARI - FIRMWARE YÜKSELTME & LOCAL-IN KORUMA]\nexecute backup config flash "pre_7413_upgrade"\nconfig system interface\n    edit "<wan_interface>"\n        unselect allowaccess fgfm https ssh http\n    next\nend`,
        diagnosticCli: `get system status\ndiagnose debug crashlog read\nget system performance status`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4.13-Administration_Guide.pdf & Fortinet PSIRT"
      });
    } else if (isVersionLessThan(version, "7.4.0")) {
      addFinding({
        code: "FGT-CVE-01",
        category: "PSIRT & Firmware Zaafiyetleri (7.4 / 7.6)",
        severity: "CRITICAL",
        statusType: "MISCONFIGURED",
        title: `Eski Nesil FortiOS Sürümü (v${version}) — FortiOS 7.4.13 LTS veya 7.6.8 Geçişi Zorunlu`,
        description: `Cihazınız FortiOS ${version} çalıştırıyor. NP7/SPU donanım hızlandırması, PBKDF2 parola özetleme, Local-In Virtual Patching ve güncel PSIRT yamaları için FortiOS 7.4.13 veya 7.6.8 sürümüne yükseltilmelidir.`,
        currentConfig: `#config-version=${model}-${version}-FW-build${build}`,
        expectedConfig: `#config-version=${model}-7.4.13 veya 7.6.8`,
        remediation: `execute backup config flash "pre_upgrade_backup"`,
        diagnosticCli: `get system status\nexecute tac report`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf & Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf"
      });
    } else {
      addPassed("FGT-CVE-01", "PSIRT & Firmware Zaafiyetleri (7.4 / 7.6)", `FortiOS firmware sürümü (v${version}) güncel dalda`);
    }
  } else {
    addPassed("FGT-CVE-01", "PSIRT & Firmware Zaafiyetleri (7.4 / 7.6)", "Firmware başlığı varsayılan / uyumlu");
  }

  // ============================================================================
  // 2. SSL VPN -> IPSEC IKEv2 (UDP/TCP) & AGENTLESS VPN / ZTNA GÖÇÜ (7.4 & 7.6)
  // ============================================================================
  const sslVpnRaw = parseConfigSection(confText, "vpn ssl settings");
  const sslVpn = parseKeyValues(sslVpnRaw);
  const sslPortalsRaw = parseConfigSection(confText, "vpn ssl web portal");
  const sslPortals = parseEditBlocks(sslPortalsRaw);
  const hasSslFirewallPolicy = /set\s+(srcintf|dstintf)\s+[^\r\n]*ssl\./i.test(confText);

  const isSslVpnEnabled =
    sslVpn["status"] === "enable" ||
    (Boolean(sslVpn["source-interface"]) && sslVpn["status"] !== "disable" && (hasSslFirewallPolicy || Boolean(sslVpn["default-portal"])));

  if (isSslVpnEnabled) {
    addFinding({
      code: "FGT-SSL-01",
      category: "SSL VPN -> IPsec IKEv2 & ZTNA Göçü",
      severity: is76Branch ? "CRITICAL" : "HIGH",
      statusType: "MISCONFIGURED",
      title: is76Branch
        ? `FortiOS 7.6 Uyumsuzluğu: SSL-VPN Tunnel Mode 7.6.3+ Sürümlerinde Tamamen Kaldırıldı! (${isSslRemovedModel76 ? `${model} Modelinde SSL-VPN Desteklenmez` : "IPsec IKEv2 TCP/UDP veya ZTNA'ya Geçilmeli"})`
        : "SSL-VPN Aktif — FortiOS 7.4/7.6 Rehberine Göre IPsec IKEv2 (TCP/443 Fallback) veya ZTNA'ya Geçilmeli",
      description: is76Branch
        ? `FortiOS 7.6.3 – 7.6.8 Release Notes uyarınca SSL-VPN Tunnel Mode TÜM FortiGate modellerinden kalıcı olarak kaldırılmıştır (yükseltme sırasında silinir). Ayrıca 2GB RAM ve G-serisi giriş modellerinde (40F, 60F, 61F, 50G, 70G, 90G, 91G) Agentless VPN (Web Mode) de kaldırılmıştır. Uzaktan erişim NPU hızlandırmalı 'IPsec IKEv2 (UDP/TCP)' veya 'ZTNA Application Gateway' yapısına taşınmalıdır.`
        : `Cihaz üzerinde SSL-VPN (${sslVpn["source-interface"] || "WAN"}) aktif durumda. Fortinet 7.4 ve 7.6 Best Practices dokümanlarına göre SSL-VPN yerine NPU donanım hızlandırmalı 'IPsec IKEv2 Dial-up VPN (TCP kapsüllemesi ile)' veya 'ZTNA' kullanılmalıdır.`,
      currentConfig: `config vpn ssl settings\n    set status ${sslVpn["status"] || "enable"}\n    set source-interface "${sslVpn["source-interface"] || "wan1"}"\n    set port ${sslVpn["port"] || "443"}\nend`,
      expectedConfig: `config system settings\n    set ike-tcp-port 11443\nend\nconfig vpn ipsec phase1-interface\n    edit "Dialup_IKEv2"\n        set type dynamic\n        set ike-version 2\n        set transport udp-fallback-tcp\n        set proposal aes256gcm-prfsha384 aes256-sha256\n        set dhgrp 20 21 14\n    next\nend\nconfig vpn ssl settings\n    set status disable\n    unset source-interface\nend`,
      remediation: `# [DÜZELTME ADIMLARI - SSL-VPN KAPATMA & IPSEC IKEv2 (UDP+TCP) OLUŞTURMA]\n# Not: 7.6.1+ sürümlerinde IKE TCP portu varsayılan 443 olduğu için GUI admin-sport ile çakışmaması adına 11443 önerilir:\nconfig system settings\n    set ike-tcp-port 11443\nend\nconfig vpn ipsec phase1-interface\n    edit "Dialup_IKEv2"\n        set type dynamic\n        set interface "${(sslVpn["source-interface"] || "wan1").split(" ")[0]}"\n        set ike-version 2\n        set peertype any\n        set net-device disable\n        set mode-cfg enable\n        set proposal aes256gcm-prfsha384 aes256-sha256\n        set dhgrp 20 21 14\n        set eap enable\n        set eap-identity send-request\n        set transport udp-fallback-tcp\n        set ipv4-start-ip 10.212.134.10\n        set ipv4-end-ip 10.212.134.200\n        set dpd on-idle\n    next\nend\nconfig vpn ssl settings\n    set status disable\n    unset source-interface\nend`,
      diagnosticCli: `get vpn ssl monitor\ndiagnose vpn ssl statistics\ndiagnose vpn ike gateway list`,
      reference: "Fortinet Resmi Dokümanı (7.6): fortios-v7.6.8-release-notes.pdf & Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-New_Features_Guide.pdf (s. 577)"
    });

    const webModePortals = sslPortals.filter(p => p.settings["web-mode"] === "enable");
    if (webModePortals.length > 0) {
      addFinding({
        code: "FGT-SSL-02",
        category: "SSL VPN -> IPsec IKEv2 & ZTNA Göçü",
        severity: "CRITICAL",
        statusType: "MISCONFIGURED",
        title: `SSL-VPN Web Mode (7.6 Agentless VPN) Aktif (${webModePortals.map(p => p.id).join(", ")})`,
        description: "SSL-VPN portallarında 'web-mode enable' açık. Fortinet PSIRT verilerine göre SSL-VPN RCE zafiyetlerinin büyük çoğunluğu Web Portal bileşeninden kaynaklanmaktadır. Web uygulamalarına istemcisiz erişim gerekiyorsa FortiOS 7.6 ZTNA Agentless Web Portal kullanılmalıdır.",
        currentConfig: `config vpn ssl web portal\n${webModePortals.map(p => `    edit "${p.id}"\n        set web-mode enable\n    next`).join("\n")}\nend`,
        expectedConfig: `config vpn ssl web portal\n${webModePortals.map(p => `    edit "${p.id}"\n        set web-mode disable\n    next`).join("\n")}\nend`,
        remediation: `# [DÜZELTME ADIMLARI - MEVCUT PORTALLARDA WEB-MODE KAPATMA]\nconfig vpn ssl web portal\n${webModePortals.map(p => `    edit "${p.id}"\n        set web-mode disable\n    next`).join("\n")}\nend`,
        diagnosticCli: `show vpn ssl web portal`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf & Fortinet Resmi Dokümanı (7.6): ZTNA_for_Web_Applications-7.6.3-Deployment_Guide.pdf"
      });
    } else {
      addPassed("FGT-SSL-02", "SSL VPN -> IPsec IKEv2 & ZTNA Göçü", "SSL-VPN portallarında Web-Mode kapalı");
    }

    if (!sslVpn["source-address"] || sslVpn["source-address"] === "all") {
      addFinding({
        code: "FGT-SSL-03",
        category: "SSL VPN -> IPsec IKEv2 & ZTNA Göçü",
        severity: "HIGH",
        statusType: sslVpn["source-address"] ? "MISCONFIGURED" : "MISSING",
        title: "SSL-VPN Tüm Dünya IP Adreslerine ('all') Açık — GeoIP Kısıtlaması Yok",
        description: "SSL-VPN ayarlarında 'source-address' tüm dünyaya ('all') açık bırakılmış. Yurt dışı kaynaklı botnet parola taramalarını engellemek için sadece hizmet verilen ülke (Örn: Türkiye) tanımlanmalıdır.",
        currentConfig: `config vpn ssl settings\n    set source-address "${sslVpn["source-address"] || "all"}"\nend`,
        expectedConfig: `config firewall address\n    edit "GEO_TURKEY"\n        set type geography\n        set country "TR"\n    next\nend\nconfig vpn ssl settings\n    set source-address "GEO_TURKEY"\nend`,
        remediation: `# [EKLEME & DÜZELTME ADIMLARI - GEOIP ADRESİ EKLEME VE SSL-VPN SINIRLAMA]\nconfig firewall address\n    edit "GEO_TURKEY"\n        set type geography\n        set country "TR"\n    next\nend\nconfig vpn ssl settings\n    set source-address "GEO_TURKEY"\nend`,
        diagnosticCli: `diagnose vpn ssl mux-stat\nexecute log filter category 1\nexecute log display`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4.13-Administration_Guide.pdf"
      });
    } else {
      addPassed("FGT-SSL-03", "SSL VPN -> IPsec IKEv2 & ZTNA Göçü", "SSL-VPN kaynak adres (GeoIP/IP) kısıtlaması mevcut");
    }

    if (sslVpn["tlsv1-0"] === "enable" || sslVpn["tlsv1-1"] === "enable" || sslVpn["algorithm"] === "low" || sslVpn["algorithm"] === "medium") {
      addFinding({
        code: "FGT-SSL-04",
        category: "SSL VPN -> IPsec IKEv2 & ZTNA Göçü",
        severity: "HIGH",
        statusType: "MISCONFIGURED",
        title: "SSL-VPN'de Eski TLS Sürümleri (TLS 1.0/1.1) veya Zayıf Şifreleme Aktif",
        description: "SSL-VPN üzerinde TLS 1.0/1.1 protokollerine veya zayıf algoritmalara izin verilmektedir. Sadece TLS 1.2 ve TLS 1.3 aktif olmalıdır.",
        currentConfig: `config vpn ssl settings\n    set tlsv1-0 ${sslVpn["tlsv1-0"] || "disable"}\n    set tlsv1-1 ${sslVpn["tlsv1-1"] || "disable"}\n    set algorithm ${sslVpn["algorithm"] || "high"}\nend`,
        expectedConfig: `config vpn ssl settings\n    set tlsv1-0 disable\n    set tlsv1-1 disable\n    set tlsv1-2 enable\n    set tlsv1-3 enable\n    set algorithm high\n    set banned-cipher RSA SHA1 SHA256 SHA384\nend`,
        remediation: `# [DÜZELTME ADIMLARI - SSL-VPN KRİPTO SIKILAŞTIRMA]\nconfig vpn ssl settings\n    set tlsv1-0 disable\n    set tlsv1-1 disable\n    set tlsv1-2 enable\n    set tlsv1-3 enable\n    set algorithm high\n    set banned-cipher RSA SHA1 SHA256 SHA384\nend`,
        diagnosticCli: `show full-configuration vpn ssl settings | grep tls`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf"
      });
    } else {
      addPassed("FGT-SSL-04", "SSL VPN -> IPsec IKEv2 & ZTNA Göçü", "SSL-VPN TLS protokol ve algoritmaları güçlü");
    }

    const loginLimit = parseInt(sslVpn["login-attempt-limit"] || "2", 10);
    const blockTime = parseInt(sslVpn["login-block-time"] || "60", 10);
    if (loginLimit > 3 || blockTime < 180) {
      addFinding({
        code: "FGT-SSL-05",
        category: "SSL VPN -> IPsec IKEv2 & ZTNA Göçü",
        severity: "LOW",
        statusType: "MISCONFIGURED",
        title: "SSL-VPN Brute-Force Engelleme Süresi ve Oturum Zaman Aşımı Sıkılaştırılmalı",
        description: `SSL-VPN hatalı giriş limiti (${loginLimit}) ve bloklama süresi (${blockTime} sn) otomatik parola deneme saldırılarına karşı artırılabilir.`,
        currentConfig: `config vpn ssl settings\n    set login-attempt-limit ${loginLimit}\n    set login-block-time ${blockTime}\nend`,
        expectedConfig: `config vpn ssl settings\n    set login-attempt-limit 2\n    set login-block-time 600\n    set auth-timeout 28800\n    set idle-timeout 900\nend`,
        remediation: `# [DÜZELTME ADIMLARI - SSL-VPN ZAMANLAYICI GÜNCELLEME]\nconfig vpn ssl settings\n    set login-attempt-limit 2\n    set login-block-time 600\n    set auth-timeout 28800\n    set idle-timeout 900\nend`,
        diagnosticCli: `diagnose vpn ssl blocklist list`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf"
      });
    } else {
      addPassed("FGT-SSL-05", "SSL VPN -> IPsec IKEv2 & ZTNA Göçü", "SSL-VPN brute-force koruma parametreleri uygun");
    }
  } else {
    addPassed("FGT-SSL-01", "SSL VPN -> IPsec IKEv2 & ZTNA Göçü", "SSL-VPN devre dışı (Saldırı yüzeyi kapatılmış)");
    addPassed("FGT-SSL-02", "SSL VPN -> IPsec IKEv2 & ZTNA Göçü", "SSL-VPN Web-Mode saldırı yüzeyi kapalı");
    addPassed("FGT-SSL-03", "SSL VPN -> IPsec IKEv2 & ZTNA Göçü", "SSL-VPN dış erişime kapalı");
  }

  // ============================================================================
  // 3. YÖNETİM GÜVENLİĞİ & SYSTEM GLOBAL (7.4.13 & 7.6.8 BEST PRACTICES)
  // ============================================================================
  const lockoutThreshold = parseInt(sysGlobal["admin-lockout-threshold"] || "3", 10);
  const lockoutDuration = parseInt(sysGlobal["admin-lockout-duration"] || "60", 10);
  if (lockoutThreshold > 3 || lockoutDuration < 300) {
    addFinding({
      code: "FGT-ADM-01",
      category: "Yönetim Güvenliği (System Global)",
      severity: "MEDIUM",
      statusType: sysGlobal["admin-lockout-duration"] ? "MISCONFIGURED" : "MISSING",
      title: "Yönetici Brute-Force Kilitlenme (admin-lockout) Parametreleri Zayıf",
      description: `Mevcut ayarlarda hatalı giriş eşiği ${lockoutThreshold} deneme ve kilitlenme süresi ${lockoutDuration} saniyedir. Fortinet Best Practices ve CIS Benchmark en fazla 3 deneme ve en az 300 saniye kilitlenme süresi şart koşar.`,
      currentConfig: `config system global\n    set admin-lockout-threshold ${lockoutThreshold}\n    set admin-lockout-duration ${lockoutDuration}\nend`,
      expectedConfig: `config system global\n    set admin-lockout-threshold 3\n    set admin-lockout-duration 300\nend`,
      remediation: `# [DÜZELTME ADIMLARI - BRUTE-FORCE KİLİTLENME SÜRESİ]\nconfig system global\n    set admin-lockout-threshold 3\n    set admin-lockout-duration 300\nend`,
      diagnosticCli: `get system global | grep admin-lockout`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & CIS Benchmark 1.2.1"
    });
  } else {
    addPassed("FGT-ADM-01", "Yönetim Güvenliği (System Global)", "Yönetici brute-force kilitlenme ayarları uygun");
  }

  const adminTimeout = parseInt(sysGlobal["admintimeout"] || "5", 10);
  if (adminTimeout > 10) {
    addFinding({
      code: "FGT-ADM-02",
      category: "Yönetim Güvenliği (System Global)",
      severity: "LOW",
      statusType: "MISCONFIGURED",
      title: `Yönetici Boşta Kalma Zaman Aşımı (${adminTimeout} dk) Çok Uzun`,
      description: `Yönetim arayüzü boşta kalma süresi ${adminTimeout} dakika olarak yapılandırılmış. Açık unutulan oturumların ele geçirilmesini önlemek için maksimum 5 dakika olmalıdır.`,
      currentConfig: `config system global\n    set admintimeout ${adminTimeout}\nend`,
      expectedConfig: `config system global\n    set admintimeout 5\nend`,
      remediation: `# [DÜZELTME ADIMLARI - IDLE TIMEOUT DÜŞÜRME]\nconfig system global\n    set admintimeout 5\nend`,
      diagnosticCli: `get system info admin status`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf (Idle Timeout)"
    });
  } else {
    addPassed("FGT-ADM-02", "Yönetim Güvenliği (System Global)", "Yönetici oturum zaman aşımı süresi (<=10 dk) uygun");
  }

  const adminSport = sysGlobal["admin-sport"] || "443";
  const adminSshPort = sysGlobal["admin-ssh-port"] || "22";
  if (adminSport === "443" || adminSshPort === "22") {
    addFinding({
      code: "FGT-ADM-03",
      category: "Yönetim Güvenliği (System Global)",
      severity: "MEDIUM",
      statusType: (sysGlobal["admin-sport"] || sysGlobal["admin-ssh-port"]) ? "MISCONFIGURED" : "MISSING",
      title: `Varsayılan Yönetim Portları Kullanılıyor (HTTPS: ${adminSport}, SSH: ${adminSshPort}) — 7.6 IKE-TCP Çakışma Riski`,
      description: "Yönetim servislerinin standart 443 ve 22 portlarında çalışması hem otomatik taramalara hedef olmayı kolaylaştırır hem de FortiOS 7.6.1+ sürümlerinde varsayılan IKE-TCP portu (443) ile çakışarak GUI erişimini engelleyebilir (7.6.8 Release Notes).",
      currentConfig: `config system global\n    set admin-sport ${adminSport}\n    set admin-ssh-port ${adminSshPort}\nend`,
      expectedConfig: `config system global\n    set admin-sport 8443\n    set admin-ssh-port 2222\n    set admin-https-redirect disable\n    set admin-host "<kurumsal-fqdn>"\nend`,
      remediation: `# [DÜZELTME ADIMLARI - YÖNETİM PORTLARINI DEĞİŞTİRME & HOST HEADER KORUMASI]\nconfig system global\n    set admin-sport 8443\n    set admin-ssh-port 2222\n    set admin-https-redirect disable\nend`,
      diagnosticCli: `show system global | grep admin-`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & fortios-v7.6.8-release-notes.pdf"
    });
  } else {
    addPassed("FGT-ADM-03", "Yönetim Güvenliği (System Global)", "Varsayılan yönetim portları (443/22) değiştirilmiş");
  }

  const isWeakGlobalCrypto =
    sysGlobal["strong-crypto"] === "disable" ||
    sysGlobal["ssl-static-key-ciphers"] === "enable" ||
    (sysGlobal["dh-params"] && parseInt(sysGlobal["dh-params"], 10) < 3072) ||
    (sysGlobal["admin-https-ssl-versions"] && /tlsv1-0|tlsv1-1/.test(sysGlobal["admin-https-ssl-versions"]));

  if (isWeakGlobalCrypto) {
    addFinding({
      code: "FGT-ADM-04",
      category: "Kriptografi & Yönetim Güvenliği",
      severity: "HIGH",
      statusType: "MISCONFIGURED",
      title: "Strong-Crypto Devre Dışı, Zayıf DH-Params (<3072) veya Eski TLS Sürümü Aktif",
      description: "FortiOS 7.4 ve 7.6 Best Practices rehberine göre 'strong-crypto enable', 'ssl-static-key-ciphers disable', 'dh-params 8192' (veya en az 3072) ve 'admin-https-ssl-versions tlsv1-2 tlsv1-3' olmalıdır.",
      currentConfig: `config system global\n    set strong-crypto ${sysGlobal["strong-crypto"] || "enable"}\n    set ssl-static-key-ciphers ${sysGlobal["ssl-static-key-ciphers"] || "enable"}\n    set dh-params ${sysGlobal["dh-params"] || "2048"}\n    set admin-https-ssl-versions ${sysGlobal["admin-https-ssl-versions"] || "tlsv1-2 tlsv1-3"}\nend`,
      expectedConfig: `config system global\n    set strong-crypto enable\n    set ssl-static-key-ciphers disable\n    set dh-params 8192\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\n    set ssl-min-proto-version TLSv1-2\nend`,
      remediation: `# [DÜZELTME ADIMLARI - GLOBAL KRİPTOGRAFİ SIKILAŞTIRMA]\nconfig system global\n    set strong-crypto enable\n    set ssl-static-key-ciphers disable\n    set dh-params 8192\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\n    set ssl-min-proto-version TLSv1-2\nend`,
      diagnosticCli: `show full-configuration system global | grep -E "crypto|ssl|dh-params"`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf"
    });
  } else {
    addPassed("FGT-ADM-04", "Kriptografi & Yönetim Güvenliği", "Strong-crypto ve TLS 1.2/1.3 zorunluluğu aktif");
  }

  if (sysGlobal["pre-login-banner"] !== "enable") {
    addFinding({
      code: "FGT-ADM-05",
      category: "Uyumluluk & Yönetim (Compliance)",
      severity: "LOW",
      statusType: sysGlobal["pre-login-banner"] ? "MISCONFIGURED" : "MISSING",
      title: "Giriş Öncesi Yasal Uyarı Banner'ı (pre-login-banner) Aktif Değil",
      description: "ISO 27001, PCI-DSS ve CIS Benchmark standartları gereği yetkisiz erişimlere karşı oturum açma öncesinde yasal uyarı mesajı gösterilmelidir.",
      currentConfig: `config system global\n    set pre-login-banner ${sysGlobal["pre-login-banner"] || "disable"}\nend`,
      expectedConfig: `config system global\n    set pre-login-banner enable\n    set post-login-banner enable\nend`,
      remediation: `# [EKLEME / DÜZELTME ADIMLARI - YASAL UYARI BANNER'I AÇMA]\nconfig system global\n    set pre-login-banner enable\n    set post-login-banner enable\nend`,
      diagnosticCli: `get system global | grep banner`,
      reference: "CIS FortiGate 7.4 / 7.6 Benchmark - 1.1"
    });
  } else {
    addPassed("FGT-ADM-05", "Uyumluluk & Yönetim (Compliance)", "Giriş öncesi yasal uyarı banner'ı aktif");
  }

  const autoInstallRaw = parseConfigSection(confText, "system auto-install");
  const autoInstall = parseKeyValues(autoInstallRaw);
  if (autoInstall["auto-install-config"] === "enable" || autoInstall["auto-install-image"] === "enable") {
    addFinding({
      code: "FGT-ADM-06",
      category: "Fiziksel & Donanım Güvenliği",
      severity: "MEDIUM",
      statusType: "MISCONFIGURED",
      title: "USB Üzerinden Otomatik Konfigürasyon / Firmware Yükleme (auto-install) Açık",
      description: "Cihaza fiziksel erişimi olan yetkisiz bir kişinin USB bellek takarak cihaz konfigürasyonunu veya işletim sistemini değiştirmesini önlemek için auto-install kapatılmalıdır.",
      currentConfig: `config system auto-install\n    set auto-install-config ${autoInstall["auto-install-config"] || "disable"}\n    set auto-install-image ${autoInstall["auto-install-image"] || "disable"}\nend`,
      expectedConfig: `config system auto-install\n    set auto-install-config disable\n    set auto-install-image disable\nend`,
      remediation: `# [DÜZELTME ADIMLARI - USB OTOMATİK KURULUMU KAPATMA]\nconfig system auto-install\n    set auto-install-config disable\n    set auto-install-image disable\nend`,
      diagnosticCli: `show full-configuration system auto-install`,
      reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf & Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf"
    });
  } else {
    addPassed("FGT-ADM-06", "Fiziksel & Donanım Güvenliği", "USB otomatik kurulum (auto-install) güvenli");
  }

  const pwdPolicyRaw = parseConfigSection(confText, "system password-policy");
  const pwdPolicy = parseKeyValues(pwdPolicyRaw);
  if (pwdPolicy["status"] !== "enable" || parseInt(pwdPolicy["minimum-length"] || "8", 10) < 12) {
    addFinding({
      code: "FGT-ADM-07",
      category: "Yönetim Güvenliği (Kimlik Doğrulama)",
      severity: "HIGH",
      statusType: pwdPolicyRaw.trim() ? "MISCONFIGURED" : "MISSING",
      title: "Yönetici Parola Karmaşıklık Politikası (Password Policy) Kapalı veya <12 Karakter (7.6.5+ Zorunlu Standart)",
      description: "FortiOS 7.6.5+ sürümlerinde varsayılan olarak zorunlu hale getirilen en az 12 karakterli karmaşık parola politikası ve parola tekrar kullanım engeli ('set reuse-password disable') aktif değil.",
      currentConfig: pwdPolicyRaw.trim()
        ? `config system password-policy\n${pwdPolicyRaw.trim()}\nend`
        : `# 'config system password-policy' bloğu tanımlanmamış (Varsayılan: status disable)`,
      expectedConfig: `config system password-policy\n    set status enable\n    set apply-to admin-password ipsec-preshared-key\n    set minimum-length 12\n    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n    set min-non-alphanumeric 1\n    set min-number 1\n    set expire-status enable\n    set expire-day 90\n    set reuse-password disable\n    set reuse-password-limit 5\nend`,
      remediation: `# [${pwdPolicyRaw.trim() ? "DÜZELTME" : "EKLEME"} ADIMLARI - PAROLA POLİTİKASI TANIMLAMA]\nconfig system password-policy\n    set status enable\n    set apply-to admin-password ipsec-preshared-key\n    set minimum-length 12\n    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n    set min-non-alphanumeric 1\n    set min-number 1\n    set expire-status enable\n    set expire-day 90\n    set reuse-password disable\n    set reuse-password-limit 5\nend`,
      diagnosticCli: `show system password-policy`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & fortios-v7.6.8-release-notes.pdf"
    });
  } else {
    addPassed("FGT-ADM-07", "Yönetim Güvenliği (Kimlik Doğrulama)", "Güçlü parola politikası (>=12 karakter) aktif");
  }

  // Hairpin Traffic Redirect (7.6.5+ Best Practice)
  if (sysGlobal["allow-traffic-redirect"] === "enable" || sysGlobal["ipv6-allow-traffic-redirect"] === "enable") {
    addFinding({
      code: "FGT-ADM-11",
      category: "Ağ Sıkılaştırma & Yönlendirme (7.6.5+)",
      severity: "MEDIUM",
      statusType: "MISCONFIGURED",
      title: "Aynı Arayüzden Dönen (Hairpin) Trafiğin Firewall Kural Kontrolünü Atlaması Açık (allow-traffic-redirect)",
      description: "FortiOS 7.6.5+ ile güvenlik amacıyla varsayılan olarak kapatılan 'allow-traffic-redirect' ayarı açık bırakılmış. Aynı arayüze giren ve çıkan yönlendirilmiş paketlerin firewall politikasını atlamaması için kapatılmalıdır.",
      currentConfig: `config system global\n    set allow-traffic-redirect ${sysGlobal["allow-traffic-redirect"] || "enable"}\nend`,
      expectedConfig: `config system global\n    set allow-traffic-redirect disable\n    set ipv6-allow-traffic-redirect disable\nend`,
      remediation: `# [DÜZELTME ADIMLARI - HAIRPIN TRAFİK POLİTİKA DENETİMİ]\nconfig system global\n    set allow-traffic-redirect disable\n    set ipv6-allow-traffic-redirect disable\nend`,
      diagnosticCli: `show full-configuration system global | grep traffic-redirect`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & fortios-v7.6.8-release-notes.pdf"
    });
  } else {
    addPassed("FGT-ADM-11", "Ağ Sıkılaştırma & Yönlendirme (7.6.5+)", "Hairpin trafik yönlendirme kontrolü güvenli");
  }

  const sysAdminRaw = parseConfigSection(confText, "system admin");
  const adminBlocks = parseEditBlocks(sysAdminRaw);
  if (adminBlocks.length > 0) {
    const hasDefaultAdmin = adminBlocks.some(b => b.id.toLowerCase() === "admin");
    if (hasDefaultAdmin) {
      addFinding({
        code: "FGT-ADM-08",
        category: "Yönetici Hesapları (System Admin)",
        severity: "MEDIUM",
        statusType: "MISCONFIGURED",
        title: "Varsayılan 'admin' Kullanıcı Hesabı Aktif",
        description: "Brute-force saldırılarında ilk hedef alınan hesap adı 'admin'dir. Farklı isimde bir super_admin oluşturulup varsayılan 'admin' silinmelidir.",
        currentConfig: `config system admin\n    edit "admin"\n        set accprofile "super_admin"\n    next\nend`,
        expectedConfig: `config system admin\n    edit "netsec_admin"\n        set accprofile "super_admin"\n        set trusthost1 10.10.10.0 255.255.255.0\n        set two-factor fortitoken\n    next\n    delete "admin"\nend`,
        remediation: `# [DÜZELTME ADIMLARI - YENİ SUPER_ADMIN EKLEME VE VARSAYILAN ADMIN SİLME]\nconfig system admin\n    edit "netsec_admin"\n        set accprofile "super_admin"\n        set trusthost1 10.10.10.0 255.255.255.0\n        set password <Guclu_Parola>\n    next\n    delete "admin"\nend`,
        diagnosticCli: `get system admin list\nget system info admin status`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf (Administrators)"
      });
    } else {
      addPassed("FGT-ADM-08", "Yönetici Hesapları (System Admin)", "Varsayılan 'admin' hesabı kaldırılmış");
    }

    const untrustedAdmins = adminBlocks.filter(
      b => !b.settings["trusthost1"] || b.settings["trusthost1"].startsWith("0.0.0.0")
    );
    if (untrustedAdmins.length > 0) {
      const hasZeroTrusthost = untrustedAdmins.some(b => b.settings["trusthost1"] && b.settings["trusthost1"].startsWith("0.0.0.0"));
      addFinding({
        code: "FGT-ADM-09",
        category: "Yönetici Hesapları (System Admin)",
        severity: "CRITICAL",
        statusType: hasZeroTrusthost ? "MISCONFIGURED" : "MISSING",
        title: `Trusted Host (Güvenilir IP) Kısıtlaması Olmayan Yöneticiler: ${untrustedAdmins.map(a => a.id).join(", ")}`,
        description: `Toplam ${untrustedAdmins.length} yönetici hesabında 'trusthost1' tanımlanmamış veya '0.0.0.0/0' bırakılmış. Yönetim erişimi olan herhangi bir arayüzden herhangi bir IP adresiyle giriş denemesi yapılabilir.`,
        currentConfig: `config system admin\n${untrustedAdmins.map(a => `    edit "${a.id}"\n        ${a.settings["trusthost1"] ? `set trusthost1 ${a.settings["trusthost1"]}` : "# trusthost1 tanımlanmamış (Eksik)"}\n    next`).join("\n")}\nend`,
        expectedConfig: `config system admin\n${untrustedAdmins.map(a => `    edit "${a.id}"\n        set trusthost1 10.0.0.0 255.255.255.0\n    next`).join("\n")}\nend`,
        remediation: `# [${hasZeroTrusthost ? "DÜZELTME" : "EKLEME"} ADIMLARI - YÖNETİCİLERE TRUSTED HOST EKLEME]\nconfig system admin\n${untrustedAdmins.map(a => `    edit "${a.id}"\n        set trusthost1 10.0.0.0 255.255.255.0\n    next`).join("\n")}\nend`,
        diagnosticCli: `show system admin`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4.13-Administration_Guide.pdf & Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.8-Administration_Guide.pdf"
      });
    } else {
      addPassed("FGT-ADM-09", "Yönetici Hesapları (System Admin)", "Tüm yöneticilerde Trusted Host IP kısıtlaması tanımlı");
    }

    const no2faAdmins = adminBlocks.filter(
      b => (!b.settings["two-factor"] || b.settings["two-factor"] === "disable") && !b.settings["remote-auth"]
    );
    if (no2faAdmins.length > 0) {
      addFinding({
        code: "FGT-ADM-10",
        category: "Yönetici Hesapları (System Admin)",
        severity: "HIGH",
        statusType: "MISSING",
        title: `İki Faktörlü Kimlik Doğrulama (2FA / FortiToken) Eksik Yöneticiler: ${no2faAdmins.map(a => a.id).join(", ")}`,
        description: "Lokal yönetici hesaplarında çok faktörlü kimlik doğrulama (FortiToken / Email / TOTP) tanımlanmamış.",
        currentConfig: `config system admin\n${no2faAdmins.map(a => `    edit "${a.id}"\n        # two-factor tanımlanmamış (Eksik)\n    next`).join("\n")}\nend`,
        expectedConfig: `config system admin\n${no2faAdmins.map(a => `    edit "${a.id}"\n        set two-factor fortitoken\n    next`).join("\n")}\nend`,
        remediation: `# [EKLEME ADIMLARI - YÖNETİCİ HESAPLARINA 2FA EKLEME]\nconfig system admin\n${no2faAdmins.map(a => `    edit "${a.id}"\n        set two-factor fortitoken\n    next`).join("\n")}\nend`,
        diagnosticCli: `diagnose fortitoken info\ndiagnose debug application fnbamd -1`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf (Multi-factor Authentication)"
      });
    } else {
      addPassed("FGT-ADM-10", "Yönetici Hesapları (System Admin)", "Yönetici hesaplarında 2FA aktif");
    }

    // PBKDF2 Password Hash Check (7.4.8+ / 7.6.1+)
    const legacyHashAdmins = adminBlocks.filter(
      b => b.settings["password"] && /^ENC\s+SH2/i.test(b.settings["password"])
    );
    if (legacyHashAdmins.length > 0) {
      addFinding({
        code: "FGT-ADM-12",
        category: "Yönetim Güvenliği (Kimlik Doğrulama)",
        severity: "MEDIUM",
        statusType: "MISCONFIGURED",
        title: `Eski SHA256 (SH2) Parola Özeti Kullanan Yöneticiler — PBKDF2 (PB2) Formatına Geçilmeli: ${legacyHashAdmins.map(a => a.id).join(", ")}`,
        description: "FortiOS 7.4.8+ ve 7.6.1+ sürümleri yönetici parolalarını çevrimdışı kırma saldırılarına dirençli PBKDF2 (ENC PB2...) algoritmasıyla saklar. Eski sürümden yükseltilen cihazlarda 'ENC SH2...' kalmışsa parolalar yenilenmelidir.",
        currentConfig: `config system admin\n${legacyHashAdmins.map(a => `    edit "${a.id}"\n        set password ENC SH2... (Eski SHA256 Hash)\n    next`).join("\n")}\nend`,
        expectedConfig: `config system admin\n${legacyHashAdmins.map(a => `    edit "${a.id}"\n        set password ENC PB2... (PBKDF2 Hash)\n    next`).join("\n")}\nend`,
        remediation: `# [DÜZELTME ADIMLARI - PAROLAYI PBKDF2 FORMATINA DÖNÜŞTÜRME]\nconfig system admin\n${legacyHashAdmins.map(a => `    edit "${a.id}"\n        set password <Yeni_Guclu_Parola>\n    next`).join("\n")}\nend`,
        diagnosticCli: `show system admin | grep -E "edit|password"`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-New_Features_Guide.pdf (s. 882 PBKDF2 Passwords)"
      });
    } else {
      addPassed("FGT-ADM-12", "Yönetim Güvenliği (Kimlik Doğrulama)", "Yönetici parola özetleri PBKDF2 / güncel formatta");
    }
  }

  // ============================================================================
  // 4. ARAYÜZ GÜVENLİĞİ, LOCAL-IN VIRTUAL PATCHING & PORT KAPATMA (7.4 & 7.6)
  // ============================================================================
  const sysIntfRaw = parseConfigSection(confText, "system interface");
  const intfBlocks = parseEditBlocks(sysIntfRaw);
  const insecureCleartextIntf = [];
  const wanExposedMgmtIntf = [];
  const fgfmExposedIntf = [];

  for (const intf of intfBlocks) {
    const access = (intf.settings["allowaccess"] || "").split(/\s+/).filter(Boolean);
    const role = (intf.settings["role"] || "").toLowerCase();
    const isWan =
      role === "wan" ||
      /^(wan\d*|internet|untrust|ext|pppoe)/i.test(intf.id) ||
      /wan|internet|untrust|metro|dsl/i.test(intf.settings["alias"] || "");

    if (access.some(a => ["http", "telnet"].includes(a))) {
      insecureCleartextIntf.push({ id: intf.id, access: access.join(" ") });
    }
    if (isWan && access.some(a => ["https", "ssh", "http", "telnet", "snmp", "fgfm", "radius-acct", "ftm"].includes(a))) {
      wanExposedMgmtIntf.push({ id: intf.id, access: access.join(" ") });
    }
    if (access.includes("fgfm")) {
      fgfmExposedIntf.push({ id: intf.id, access: access.join(" ") });
    }
  }

  if (wanExposedMgmtIntf.length > 0) {
    addFinding({
      code: "FGT-NET-01",
      category: "Arayüz & Saldırı Yüzeyi (WAN)",
      severity: "CRITICAL",
      statusType: "MISCONFIGURED",
      title: `WAN / İnternet Arayüzünde Yönetim Servisleri Açık: ${wanExposedMgmtIntf.map(i => `${i.id} [${i.access}]`).join(", ")}`,
      description: "Dış dünyaya (WAN) bakan arayüzlerde HTTPS, SSH, HTTP, SNMP veya FGFM erişimi açık bırakılmış.",
      currentConfig: `config system interface\n${wanExposedMgmtIntf.map(i => `    edit "${i.id}"\n        set allowaccess ${i.access}\n    next`).join("\n")}\nend`,
      expectedConfig: `config system interface\n${wanExposedMgmtIntf.map(i => `    edit "${i.id}"\n        unset allowaccess\n    next`).join("\n")}\nend`,
      remediation: `# [DÜZELTME ADIMLARI - WAN ARAYÜZÜNDE YÖNETİM ERİŞİMİNİ KALDIRMA]\nconfig system interface\n${wanExposedMgmtIntf.map(i => `    edit "${i.id}"\n        unset allowaccess\n    next`).join("\n")}\nend`,
      diagnosticCli: `show system interface | grep -f allowaccess\ndiagnose ip address list`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf (Disable Administrative Access on External Interfaces)"
    });
  } else {
    addPassed("FGT-NET-01", "Arayüz & Saldırı Yüzeyi (WAN)", "WAN arayüzlerinde yönetim erişimi kapalı");
  }

  if (insecureCleartextIntf.length > 0) {
    addFinding({
      code: "FGT-NET-02",
      category: "Arayüz & Saldırı Yüzeyi",
      severity: "HIGH",
      statusType: "MISCONFIGURED",
      title: `Şifresiz Yönetim Protokolleri (HTTP / Telnet) Açık Arayüzler: ${insecureCleartextIntf.map(i => i.id).join(", ")}`,
      description: "Ağ arayüzlerinde parolaları şifresiz (cleartext) taşıyan HTTP veya Telnet protokollerine izin verilmektedir.",
      currentConfig: `config system interface\n${insecureCleartextIntf.map(i => `    edit "${i.id}"\n        set allowaccess ${i.access}\n    next`).join("\n")}\nend`,
      expectedConfig: `config system interface\n${insecureCleartextIntf.map(i => `    edit "${i.id}"\n        unselect allowaccess http telnet\n    next`).join("\n")}\nend`,
      remediation: `# [DÜZELTME ADIMLARI - HTTP VE TELNET ERİŞİMİNİ KALDIRMA]\nconfig system interface\n${insecureCleartextIntf.map(i => `    edit "${i.id}"\n        unselect allowaccess http telnet\n    next`).join("\n")}\nend`,
      diagnosticCli: `show system interface | grep allowaccess`,
      reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf & CIS Benchmark 2.1"
    });
  } else {
    addPassed("FGT-NET-02", "Arayüz & Saldırı Yüzeyi", "Hiçbir arayüzde şifresiz HTTP/Telnet erişimi yok");
  }

  if (fgfmExposedIntf.length > 0) {
    addFinding({
      code: "FGT-NET-03",
      category: "Arayüz & Saldırı Yüzeyi",
      severity: "HIGH",
      statusType: "MISCONFIGURED",
      title: `FGFM (FortiManager TCP/541) Protokolü Açık Arayüzler: ${fgfmExposedIntf.map(i => i.id).join(", ")}`,
      description: "Arayüzlerde 'fgfm' erişimi açık. Aktif bir FortiManager kullanılmıyorsa CVE-2024-23113 ve CVE-2024-47575 gibi zafiyetlerden korunmak için fgfm erişimi kaldırılmalıdır.",
      currentConfig: `config system interface\n${fgfmExposedIntf.map(i => `    edit "${i.id}"\n        set allowaccess ${i.access}\n    next`).join("\n")}\nend`,
      expectedConfig: `config system interface\n${fgfmExposedIntf.map(i => `    edit "${i.id}"\n        unselect allowaccess fgfm\n    next`).join("\n")}\nend`,
      remediation: `# [DÜZELTME ADIMLARI - GEREKSİZ FGFM TCP/541 ERİŞİMİNİ KAPATMA]\nconfig system interface\n${fgfmExposedIntf.map(i => `    edit "${i.id}"\n        unselect allowaccess fgfm\n    next`).join("\n")}\nend`,
      diagnosticCli: `diagnose fgfm session-list\nget system central-management`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Ports.pdf (TCP/541 FGFM) & PSIRT FG-IR-24-029"
    });
  } else {
    addPassed("FGT-NET-03", "Arayüz & Saldırı Yüzeyi", "Gereksiz FGFM (TCP/541) erişimi kapalı");
  }

  const localInRaw = parseConfigSection(confText, "firewall local-in-policy");
  const localInBlocks = parseEditBlocks(localInRaw);
  if (localInBlocks.length === 0) {
    addFinding({
      code: "FGT-NET-04",
      category: "Ağ Sıkılaştırma (Local-In & Virtual Patch)",
      severity: "HIGH",
      statusType: "MISSING",
      title: "Local-In Policy ve ISDB Malicious/Tor Engelleme Kuralı Eksik (7.4.4+ & 7.6.1+ Standardı)",
      description: "FortiGate'in kendi üzerindeki servislere (VPN, IKE, BGP, HTTPS, SSH) gelen trafiği sınırlandıran, Tor/Malicious IP'leri engelleyen ve yönetim trafiğine 'set virtual-patch enable' uygulayan 'firewall local-in-policy' bloğu bulunamadı.",
      currentConfig: `# 'config firewall local-in-policy' bloğu konfigürasyonda yok (Eksik)`,
      expectedConfig: `config log setting\n    set local-in-policy-log enable\nend\nconfig firewall local-in-policy\n    edit 1\n        set intf "any"\n        set dstaddr "all"\n        set internet-service-src enable\n        set internet-service-src-name "Malicious-Malicious.Server" "Tor-Exit.Node" "Tor-Relay.Node"\n        set service "ALL"\n        set schedule "always"\n        set action deny\n        set logtraffic enable\n    next\n    edit 2\n        set intf "wan1"\n        set srcaddr "GEO_TURKEY"\n        set dstaddr "all"\n        set action accept\n        set service "IKE"\n        set schedule "always"\n        set virtual-patch enable\n        set logtraffic enable\n    next\nend`,
      remediation: `# [EKLEME ADIMLARI - 7.4/7.6 ISDB MALICIOUS BLOCK & VIRTUAL PATCH LOCAL-IN POLICY]\nconfig log setting\n    set local-in-policy-log enable\nend\nconfig firewall local-in-policy\n    edit 1\n        set intf "any"\n        set dstaddr "all"\n        set internet-service-src enable\n        set internet-service-src-name "Malicious-Malicious.Server" "Tor-Exit.Node" "Tor-Relay.Node"\n        set service "ALL"\n        set schedule "always"\n        set action deny\n        set logtraffic enable\n    next\n    edit 2\n        set intf "wan1"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action deny\n        set service "HTTPS" "SSH" "HTTP" "TELNET" "FGFM" "SNMP"\n        set schedule "always"\n        set logtraffic enable\n    next\nend`,
      diagnosticCli: `show firewall local-in-policy\ndiagnose firewall iprope list 10000e`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-New_Features_Guide.pdf (s. 371 Default Local-In Policy) & 7.6.0 Best Practices"
    });
  } else {
    addPassed("FGT-NET-04", "Ağ Sıkılaştırma (Local-In & Virtual Patch)", `${localInBlocks.length} adet Local-In Policy tanımlanmış`);
  }

  const dosPolicyRaw = parseConfigSection(confText, "firewall DoS-policy");
  const dosBlocks = parseEditBlocks(dosPolicyRaw);
  if (dosBlocks.length === 0) {
    addFinding({
      code: "FGT-NET-05",
      category: "Ağ Sıkılaştırma (DoS & NPU Anomaly)",
      severity: "MEDIUM",
      statusType: "MISSING",
      title: "WAN Arayüzünde IPv4 DoS Policy (SYN/UDP/Port-Scan Koruması) Eksik",
      description: "Dış arayüzden gelen hacimsel paket taşması ve port tarama saldırılarını donanım (NP7/NP7Lite/NP6 anomaly engine) seviyesinde kesmek için DoS-policy oluşturulmalıdır.",
      currentConfig: `# 'config firewall DoS-policy' bloğu konfigürasyonda yok (Eksik)`,
      expectedConfig: `config firewall DoS-policy\n    edit 1\n        set interface "wan1"\n        set srcaddr "all"\n        set dstaddr "all"\n        set service "ALL"\n        config anomaly\n            edit "tcp_syn_flood"\n                set status enable\n                set action block\n                set log enable\n                set threshold 2000\n            next\n            edit "tcp_port_scan"\n                set status enable\n                set action block\n                set log enable\n                set threshold 1000\n            next\n        end\n    next\nend`,
      remediation: `# [EKLEME ADIMLARI - WAN DOS POLICY OLUŞTURMA]\nconfig firewall DoS-policy\n    edit 1\n        set interface "wan1"\n        set srcaddr "all"\n        set dstaddr "all"\n        set service "ALL"\n        config anomaly\n            edit "tcp_syn_flood"\n                set status enable\n                set action block\n                set log enable\n                set threshold 2000\n            next\n            edit "tcp_port_scan"\n                set status enable\n                set action block\n                set log enable\n                set threshold 1000\n            next\n            edit "udp_flood"\n                set status enable\n                set action block\n                set log enable\n                set threshold 2500\n            next\n        end\n    next\nend`,
      diagnosticCli: `diagnose ips anomaly list\ndiagnose ips anomaly clear`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & fortios-hardware-acceleration-768.pdf"
    });
  } else {
    addPassed("FGT-NET-05", "Ağ Sıkılaştırma (DoS & NPU Anomaly)", "DoS Policy aktif");
  }

  // Open UTM Override Ports (8008, 8010, 8015, 8020) Check from Ports PDF & Best Practices
  const wfFgRaw = parseConfigSection(confText, "webfilter fortiguard");
  const wfFg = parseKeyValues(wfFgRaw);
  if (wfFgRaw.trim() && wfFg["close-ports"] === "disable") {
    addFinding({
      code: "FGT-NET-06",
      category: "Port & Saldırı Yüzeyi (FortiOS Ports)",
      severity: "LOW",
      statusType: "MISCONFIGURED",
      title: "WebFilter Override Portları (TCP 8008, 8010, 8015, 8020) Açık Bırakılmış (close-ports disable)",
      description: "FortiOS Ports dokümanına göre WebFilter/Application Control profilleri kullanıldığında kimlik doğrulama ve uyarı sayfaları için TCP 8008, 8010, 8015 ve 8020 portları dinlemeye açılır. PCI-DSS ve dış port taramalarında açık port çıkmaması için 'set close-ports enable' yapılmalıdır.",
      currentConfig: `config webfilter fortiguard\n    set close-ports disable\nend`,
      expectedConfig: `config webfilter fortiguard\n    set close-ports enable\nend`,
      remediation: `# [DÜZELTME ADIMLARI - KULLANILMAYAN UTM OVERRIDE PORTLARINI KAPATMA]\nconfig webfilter fortiguard\n    set close-ports enable\nend`,
      diagnosticCli: `show full-configuration webfilter fortiguard | grep close-ports`,
      reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Ports.pdf & Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Ports.pdf"
    });
  } else {
    addPassed("FGT-NET-06", "Port & Saldırı Yüzeyi (FortiOS Ports)", "WebFilter override portları (8008/8010) güvenli");
  }

  // ============================================================================
  // 5. HARDWARE ACCELERATION (NP7 / NP7Lite SoC5 / NP6 / CP10 / CP9 - 7.4 & 7.6.8)
  // ============================================================================
  const fwPolicyRaw = parseConfigSection(confText, "firewall policy");
  const fwPolicies = parseEditBlocks(fwPolicyRaw);
  const disabledAsicPolicies = fwPolicies.filter(
    p => p.settings["status"] !== "disable" &&
         (p.settings["auto-asic-offload"] === "disable" || p.settings["np-acceleration"] === "disable")
  );

  if (disabledAsicPolicies.length > 0) {
    addFinding({
      code: "FGT-HW-01",
      category: "Hardware Acceleration (NP7/NP7Lite/NP6)",
      severity: "MEDIUM",
      statusType: "MISCONFIGURED",
      title: `Firewall Kurallarında ASIC/NPU Donanım Hızlandırması Kapatılmış (Policy ID: ${disabledAsicPolicies.map(p => p.id).join(", ")})`,
      description: "FortiOS 7.4 ve 7.6.8 Hardware Acceleration rehberine göre 'set auto-asic-offload disable' ayarı oturumların NP7/NP7Lite/NP6 Fast-Path yerine doğrudan ana CPU tarafından işlenmesine ve yüksek trafikte CPU darboğazına yol açar.",
      currentConfig: `config firewall policy\n${disabledAsicPolicies.slice(0, 4).map(p => `    edit ${p.id}\n        set auto-asic-offload disable\n    next`).join("\n")}\nend`,
      expectedConfig: `config firewall policy\n${disabledAsicPolicies.slice(0, 4).map(p => `    edit ${p.id}\n        unset auto-asic-offload\n    next`).join("\n")}\nend`,
      remediation: `# [DÜZELTME ADIMLARI - FIREWALL KURALLARINDA NPU FAST-PATH AÇMA]\nconfig firewall policy\n${disabledAsicPolicies.slice(0, 6).map(p => `    edit ${p.id}\n        unset auto-asic-offload\n    next`).join("\n")}\nend`,
      diagnosticCli: `diagnose sys session list | grep -E "npu|no_ofld_reason"\ndiagnose npu np7 pdq\ndiagnose npu np7 pmon`,
      reference: "Fortinet Resmi Dokümanı (7.6): fortios-hardware-acceleration-768.pdf (s. 28-44 NP7 Fastpath)"
    });
  } else if (fwPolicies.length > 0) {
    addPassed("FGT-HW-01", "Hardware Acceleration (NP7/NP7Lite/NP6)", "Tüm aktif kurallarda NPU ASIC offload açık");
  }

  // 7.6.3+ SD-WAN Application Performance Monitoring (app-monitor) NPU Offload Warning
  const apmPolicies = fwPolicies.filter(p => p.settings["app-monitor"] === "enable");
  if (apmPolicies.length > 0) {
    addFinding({
      code: "FGT-HW-03",
      category: "Hardware Acceleration (NP7/NP7Lite/NP6)",
      severity: "LOW",
      statusType: "MISCONFIGURED",
      title: `SD-WAN Application Performance Monitoring (app-monitor) Açık Kurallarda NPU Offload Devre Dışı Kalır (Policy ID: ${apmPolicies.map(p => p.id).join(", ")})`,
      description: "FortiOS 7.6 SD-WAN Service Bundle rehberine göre bir kuralda 'set app-monitor enable' açıldığında paketlerin RTT/Jitter/ServerResponseTime ölçümü için NPU donanım hızlandırması otomatik olarak devre dışı kalır (no_ofld_reason: disabled-by-policy). Sadece spesifik uygulama kurallarında kullanılmalı, genel internet kurallarında kapatılmalıdır.",
      currentConfig: `config firewall policy\n${apmPolicies.map(p => `    edit ${p.id}\n        set app-monitor enable\n    next`).join("\n")}\nend`,
      expectedConfig: `config firewall policy\n${apmPolicies.map(p => `    edit ${p.id}\n        set app-monitor disable\n    next`).join("\n")}\nend`,
      remediation: `# [DÜZELTME ADIMLARI - GENEL KURALLARDA APP-MONITOR KAPATARAK NPU OFFLOAD GERİ KAZANMA]\nconfig firewall policy\n${apmPolicies.map(p => `    edit ${p.id}\n        set app-monitor disable\n    next`).join("\n")}\nend`,
      diagnosticCli: `diagnose sys session list | grep no_ofld_reason`,
      reference: "Fortinet Resmi Dokümanı (7.6): SD-WAN-7.6-Service_Bundle_Example_Guide.pdf & fortios-hardware-acceleration-768.pdf"
    });
  }

  const phase1Raw = parseConfigSection(confText, "vpn ipsec phase1-interface");
  const phase1Blocks = parseEditBlocks(phase1Raw);
  const disabledNpuVpn = phase1Blocks.filter(p => p.settings["npu-offload"] === "disable");
  if (disabledNpuVpn.length > 0) {
    addFinding({
      code: "FGT-HW-02",
      category: "Hardware Acceleration (NP7/NP7Lite/NP6)",
      severity: "MEDIUM",
      statusType: "MISCONFIGURED",
      title: `IPsec VPN Tünellerinde NPU Offload Kapatılmış (${disabledNpuVpn.map(p => p.id).join(", ")})`,
      description: "IPsec Faz-1 ayarlarında 'set npu-offload disable' tespit edildi. Bu ayar IPsec ESP şifreleme yükünü SPU/NP7 çipinden alıp ana CPU'ya yükler.",
      currentConfig: `config vpn ipsec phase1-interface\n${disabledNpuVpn.map(p => `    edit "${p.id}"\n        set npu-offload disable\n    next`).join("\n")}\nend`,
      expectedConfig: `config vpn ipsec phase1-interface\n${disabledNpuVpn.map(p => `    edit "${p.id}"\n        unset npu-offload\n    next`).join("\n")}\nend`,
      remediation: `# [DÜZELTME ADIMLARI - IPSEC NPU HIZLANDIRMASINI AKTİFLEŞTİRME]\nconfig vpn ipsec phase1-interface\n${disabledNpuVpn.map(p => `    edit "${p.id}"\n        unset npu-offload\n    next`).join("\n")}\nend`,
      diagnosticCli: `diagnose vpn ipsec status\ndiagnose vpn tunnel list | grep npu\ndiagnose vpn tunnel npu-debug`,
      reference: "Fortinet Resmi Dokümanı (7.6): fortios-hardware-acceleration-768.pdf (s. 69 IPsec NPU Debug)"
    });
  } else if (phase1Blocks.length > 0) {
    addPassed("FGT-HW-02", "Hardware Acceleration (NP7/NP7Lite/NP6)", "IPsec VPN tünellerinde NPU donanım hızlandırması aktif");
  }

  // ============================================================================
  // 6. FIREWALL POLİTİKALARI, VIP MATCH & NGFW WEB SECURITY (7.4 & 7.6)
  // ============================================================================
  if (fwPolicies.length > 0) {
    const activeAcceptPolicies = fwPolicies.filter(
      p => p.settings["status"] !== "disable" && p.settings["action"] === "accept"
    );
    const activeDenyPolicies = fwPolicies.filter(
      p => p.settings["status"] !== "disable" && p.settings["action"] !== "accept"
    );

    const anyAnyPolicies = activeAcceptPolicies.filter(
      p => p.settings["srcaddr"] === "all" && p.settings["dstaddr"] === "all" && p.settings["service"] === "ALL"
    );
    if (anyAnyPolicies.length > 0) {
      addFinding({
        code: "FGT-POL-01",
        category: "Firewall Politikaları (Zero Trust)",
        severity: "CRITICAL",
        statusType: "MISCONFIGURED",
        title: `Kaynak=ALL, Hedef=ALL, Servis=ALL Olan Aşırı İzinli Kurallar (Policy ID: ${anyAnyPolicies.map(p => p.id).join(", ")})`,
        description: `Toplam ${anyAnyPolicies.length} adet aktif kabul kuralında kaynak IP, hedef IP ve port/servis tamamen 'ALL' olarak bırakılmış.`,
        currentConfig: `config firewall policy\n    edit ${anyAnyPolicies[0].id}\n        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n        set service "ALL"\n    next\nend`,
        expectedConfig: `config firewall policy\n    edit ${anyAnyPolicies[0].id}\n        set srcaddr "<Spesifik_Alt_Ag_Grubu>"\n        set dstaddr "<Spesifik_Hedef_Grubu>"\n        set action accept\n        set service "HTTPS" "DNS"\n    next\nend`,
        remediation: `# [DÜZELTME ADIMLARI - AŞIRI İZİNLİ KURALI DARALTMA]\nconfig firewall policy\n    edit ${anyAnyPolicies[0].id}\n        set srcaddr "<Spesifik_Alt_Ag_Grubu>"\n        set dstaddr "<Spesifik_Hedef_Grubu>"\n        set service "HTTPS" "DNS"\n    next\nend`,
        diagnosticCli: `diagnose firewall iprope lookup <src_ip> <src_port> <dst_ip> <dst_port> <proto> <intf>`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & CIS Benchmark 3.1"
      });
    } else {
      addPassed("FGT-POL-01", "Firewall Politikaları (Zero Trust)", "Any-Any-All şeklinde aşırı izinli kural bulunmadı");
    }

    const noUtmPolicies = activeAcceptPolicies.filter(
      p => p.settings["utm-status"] !== "enable" &&
           !p.settings["av-profile"] &&
           !p.settings["ips-sensor"] &&
           !p.settings["webfilter-profile"] &&
           !p.settings["application-list"] &&
           !p.settings["dnsfilter-profile"] &&
           !p.settings["casb-profile"] &&
           !p.settings["dlp-profile"] &&
           !p.settings["virtual-patch-profile"]
    );
    if (noUtmPolicies.length > 0) {
      addFinding({
        code: "FGT-POL-02",
        category: "NGFW Web Security & UTM Profilleri",
        severity: "HIGH",
        statusType: "MISSING",
        title: `Katman-7 NGFW Güvenlik Profili (IPS / AV / WebFilter / DNS / DLP / CASB) Eksik ${noUtmPolicies.length} Kural`,
        description: `Policy ID (${noUtmPolicies.slice(0, 10).map(p => p.id).join(", ")}) kurallarında hiçbir NGFW güvenlik profili tanımlanmamış. FortiOS 7.6 NGFW Web Security Deployment Guide uyarınca IPS, AV, WebFilter, DNS Filter (DoH engelleme ile) ve SSL Inspection profilleri eklenmelidir.`,
        currentConfig: `config firewall policy\n    edit ${noUtmPolicies[0].id}\n        set action accept\n        # utm-status, ips-sensor, av-profile, webfilter-profile, dnsfilter-profile tanımlanmamış (Eksik)\n    next\nend`,
        expectedConfig: `config firewall policy\n    edit ${noUtmPolicies[0].id}\n        set utm-status enable\n        set ssl-ssh-profile "certificate-inspection"\n        set ips-sensor "high_security"\n        set av-profile "default"\n        set webfilter-profile "default"\n        set dnsfilter-profile "default"\n        set application-list "default"\n    next\nend`,
        remediation: `# [EKLEME ADIMLARI - KURALA KATMAN-7 NGFW GÜVENLİK PROFİLLERİ EKLEME]\nconfig firewall policy\n    edit ${noUtmPolicies[0].id}\n        set utm-status enable\n        set ssl-ssh-profile "certificate-inspection"\n        set ips-sensor "high_security"\n        set av-profile "default"\n        set webfilter-profile "default"\n        set dnsfilter-profile "default"\n        set application-list "default"\n    next\nend`,
        diagnosticCli: `diagnose test application ipsmonitor 1\ndiagnose test application wad 1000`,
        reference: "Fortinet Resmi Dokümanı (7.6): Deployment_Guide-7.6-NGFW_Web_Security.pdf & Architecture_Guide-7.6-Client_Web_Security.pdf"
      });
    } else {
      addPassed("FGT-POL-02", "NGFW Web Security & UTM Profilleri", "Aktif kurallarda UTM/NGFW güvenlik profilleri tanımlı");
    }

    // Deny Policy match-vip check
    const denyNoMatchVip = activeDenyPolicies.filter(p => p.settings["match-vip"] === "disable");
    if (denyNoMatchVip.length > 0) {
      addFinding({
        code: "FGT-POL-05",
        category: "Firewall Politikaları (Zero Trust)",
        severity: "HIGH",
        statusType: "MISCONFIGURED",
        title: `Deny (Engelleme) Kurallarında 'match-vip disable' — VIP / Port Yönlendirme Trafiği Engeli Atlayabilir (Policy ID: ${denyNoMatchVip.map(p => p.id).join(", ")})`,
        description: "Engelleme (action deny) kurallarında 'set match-vip disable' olduğunda, dışarıdan içeriye Virtual IP (DNAT) ile açılan sunuculara gelen saldırı trafiği bu engelleme kuralını atlar (FortiOS 7.4/7.6 Best Practices).",
        currentConfig: `config firewall policy\n    edit ${denyNoMatchVip[0].id}\n        set action deny\n        set match-vip disable\n    next\nend`,
        expectedConfig: `config firewall policy\n    edit ${denyNoMatchVip[0].id}\n        set action deny\n        set match-vip enable\n    next\nend`,
        remediation: `# [DÜZELTME ADIMLARI - DENY KURALLARINDA VIP EŞLEŞMESİNİ AÇMA]\nconfig firewall policy\n${denyNoMatchVip.map(p => `    edit ${p.id}\n        set match-vip enable\n    next`).join("\n")}\nend`,
        diagnosticCli: `show firewall policy ${denyNoMatchVip[0].id}`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & fortios-v7.6.8-release-notes.pdf (Feature 1298417)"
      });
    }

    const noLogPolicies = activeAcceptPolicies.filter(
      p => p.settings["logtraffic"] === "disable"
    );
    if (noLogPolicies.length > 0) {
      addFinding({
        code: "FGT-POL-03",
        category: "Loglama & Görünürlük",
        severity: "MEDIUM",
        statusType: "MISCONFIGURED",
        title: `Trafik Loglaması (logtraffic disable) Kapatılmış Kurallar (Policy ID: ${noLogPolicies.map(p => p.id).join(", ")})`,
        description: "Olay müdahalesi (DFIR), SIEM korelasyonu ve 5651 uyumluluğu için aktif kabul kurallarında trafik loglaması kapatılmamalıdır ('set logtraffic all' veya 'utm' açık olmalıdır).",
        currentConfig: `config firewall policy\n    edit ${noLogPolicies[0].id}\n        set logtraffic disable\n    next\nend`,
        expectedConfig: `config firewall policy\n    edit ${noLogPolicies[0].id}\n        set logtraffic all\n    next\nend`,
        remediation: `# [DÜZELTME ADIMLARI - TRAFİK LOGLAMASINI AKTİFLEŞTİRME]\nconfig firewall policy\n${noLogPolicies.slice(0, 6).map(p => `    edit ${p.id}\n        set logtraffic all\n    next`).join("\n")}\nend`,
        diagnosticCli: `execute log filter category 0\nexecute log display`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS_7.6.8_Log_Reference.pdf & CIS Benchmark 3.2"
      });
    } else {
      addPassed("FGT-POL-03", "Loglama & Görünürlük", "Aktif kurallarda trafik loglaması (all/utm) açık");
    }

    const unnamedPolicies = fwPolicies.filter(p => !p.settings["name"]);
    if (unnamedPolicies.length > 0) {
      addFinding({
        code: "FGT-POL-04",
        category: "Firewall Politikaları (Operasyonel)",
        severity: "LOW",
        statusType: "MISSING",
        title: `İsimlendirilmemiş (set name) Firewall Kuralları (Policy ID: ${unnamedPolicies.map(p => p.id).join(", ")})`,
        description: "Log analizinde ve denetimlerde kuralların amacını hızlıca anlamak için her kuralın açıklayıcı bir adı ('set name') olmalıdır.",
        currentConfig: `config firewall policy\n    edit ${unnamedPolicies[0].id}\n        # set name tanımlanmamış (Eksik)\n    next\nend`,
        expectedConfig: `config firewall policy\n    edit ${unnamedPolicies[0].id}\n        set name "LAN_to_WAN_Outbound"\n    next\nend`,
        remediation: `# [EKLEME ADIMLARI - KURAL İSİMLENDİRME]\nconfig firewall policy\n    edit ${unnamedPolicies[0].id}\n        set name "LAN_to_WAN_Outbound"\n    next\nend`,
        diagnosticCli: `show firewall policy | grep -f name`,
        reference: "Fortinet Resmi Dokümanı (7.4): FortiOS-7.4-Best_Practices.pdf & Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf"
      });
    } else {
      addPassed("FGT-POL-04", "Firewall Politikaları (Operasyonel)", "Tüm firewall kuralları isimlendirilmiş");
    }
  }

  // ============================================================================
  // 7. KRİPTOGRAFİ, IPSEC VPN & PQC (7.4 & 7.6)
  // ============================================================================
  if (phase1Blocks.length > 0) {
    const weakPhase1 = phase1Blocks.filter(p => {
      const prop = p.settings["proposal"] || "";
      const dh = p.settings["dhgrp"] || "";
      return /(^|\s|-)(des|3des|md5|sha1)(\s|$|-)/i.test(prop) || /(^|\s)(1|2|5)(\s|$)/.test(dh);
    });
    if (weakPhase1.length > 0) {
      addFinding({
        code: "FGT-CRY-01",
        category: "Kriptografi & IPsec VPN",
        severity: "HIGH",
        statusType: "MISCONFIGURED",
        title: `IPsec Phase-1 Tünellerinde Zayıf Şifreleme veya DH Grubu (${weakPhase1.map(p => p.id).join(", ")})`,
        description: "IPsec Faz-1 tanımlarında DES, 3DES, MD5, SHA1 veya zayıf Diffie-Hellman grupları (DH 1, 2, 5) kullanılmaktadır. FortiOS 7.4/7.6 rehberine göre AES256-GCM ve DH grup 20/21/14 (veya 7.6 Post-Quantum PQC) kullanılmalıdır.",
        currentConfig: `config vpn ipsec phase1-interface\n${weakPhase1.map(p => `    edit "${p.id}"\n        set proposal ${p.settings["proposal"] || "des-md5"}\n        set dhgrp ${p.settings["dhgrp"] || "2"}\n    next`).join("\n")}\nend`,
        expectedConfig: `config vpn ipsec phase1-interface\n${weakPhase1.map(p => `    edit "${p.id}"\n        set ike-version 2\n        set proposal aes256gcm-prfsha384 aes256-sha256\n        set dhgrp 20 21 14\n    next`).join("\n")}\nend`,
        remediation: `# [DÜZELTME ADIMLARI - IPSEC PHASE-1 ALGORİTMA VE DH GRUBU GÜÇLENDİRME]\nconfig vpn ipsec phase1-interface\n${weakPhase1.map(p => `    edit "${p.id}"\n        set ike-version 2\n        set proposal aes256gcm-prfsha384 aes256-sha256\n        set dhgrp 20 21 14\n    next`).join("\n")}\nend`,
        diagnosticCli: `diagnose vpn ike gateway list name ${weakPhase1[0].id}`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & New Features Guide (s. 569 PQC IPsec)"
      });
    } else {
      addPassed("FGT-CRY-01", "Kriptografi & IPsec VPN", "IPsec Phase-1 şifreleme ve DH grupları güçlü");
    }

    const ikev1Tunnels = phase1Blocks.filter(p => p.settings["ike-version"] !== "2");
    if (ikev1Tunnels.length > 0) {
      addFinding({
        code: "FGT-CRY-02",
        category: "Kriptografi & IPsec VPN",
        severity: "LOW",
        statusType: "MISCONFIGURED",
        title: `IKEv1 Kullanan IPsec Tünelleri (${ikev1Tunnels.map(p => p.id).join(", ")}) — IKEv2 Önerilir`,
        description: "IKEv2; EAP kimlik doğrulama, TCP kapsüllemesi (FortiOS 7.4/7.6) ve Post-Quantum Key Exchange desteği sunduğu için tüm tünellerde IKEv2 protokolüne geçilmelidir.",
        currentConfig: `config vpn ipsec phase1-interface\n${ikev1Tunnels.map(p => `    edit "${p.id}"\n        set ike-version ${p.settings["ike-version"] || "1"}\n    next`).join("\n")}\nend`,
        expectedConfig: `config vpn ipsec phase1-interface\n${ikev1Tunnels.map(p => `    edit "${p.id}"\n        set ike-version 2\n    next`).join("\n")}\nend`,
        remediation: `# [DÜZELTME ADIMLARI - IKEv2 PROTOKOLÜNE GEÇİŞ]\nconfig vpn ipsec phase1-interface\n${ikev1Tunnels.map(p => `    edit "${p.id}"\n        set ike-version 2\n    next`).join("\n")}\nend`,
        diagnosticCli: `get vpn ipsec tunnel summary\ndiagnose vpn ike gateway flush`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6-Troubleshooting_Cheat_Sheet.pdf"
      });
    } else {
      addPassed("FGT-CRY-02", "Kriptografi & IPsec VPN", "Tüm IPsec tünellerinde IKEv2 kullanılıyor");
    }
  }

  const phase2Raw = parseConfigSection(confText, "vpn ipsec phase2-interface");
  const phase2Blocks = parseEditBlocks(phase2Raw);
  if (phase2Blocks.length > 0) {
    const weakPhase2 = phase2Blocks.filter(p => {
      const prop = p.settings["proposal"] || "";
      const pfs = p.settings["pfs"];
      return pfs === "disable" || /(^|\s|-)(des|3des|md5|sha1|null)(\s|$|-)/i.test(prop);
    });
    if (weakPhase2.length > 0) {
      addFinding({
        code: "FGT-CRY-03",
        category: "Kriptografi & IPsec VPN",
        severity: "MEDIUM",
        statusType: "MISCONFIGURED",
        title: `IPsec Phase-2'de PFS (Perfect Forward Secrecy) Kapalı veya Zayıf Algoritma (${weakPhase2.map(p => p.id).join(", ")})`,
        description: "IPsec Faz-2 ayarlarında PFS kapatılmış veya DES/3DES/MD5/SHA1 kullanılmış.",
        currentConfig: `config vpn ipsec phase2-interface\n${weakPhase2.map(p => `    edit "${p.id}"\n        set proposal ${p.settings["proposal"] || "3des-sha1"}\n        set pfs ${p.settings["pfs"] || "disable"}\n    next`).join("\n")}\nend`,
        expectedConfig: `config vpn ipsec phase2-interface\n${weakPhase2.map(p => `    edit "${p.id}"\n        set proposal aes256gcm aes256-sha256\n        set pfs enable\n        set dhgrp 20 21 14\n    next`).join("\n")}\nend`,
        remediation: `# [DÜZELTME ADIMLARI - IPSEC PHASE-2 PFS VE ALGORİTMA GÜÇLENDİRME]\nconfig vpn ipsec phase2-interface\n${weakPhase2.map(p => `    edit "${p.id}"\n        set proposal aes256gcm aes256-sha256\n        set pfs enable\n        set dhgrp 20 21 14\n    next`).join("\n")}\nend`,
        diagnosticCli: `diagnose vpn tunnel list name ${weakPhase2[0].id}\ndiagnose vpn tunnel flush ${weakPhase2[0].id}`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6-Troubleshooting_Cheat_Sheet.pdf & CIS Benchmark"
      });
    } else {
      addPassed("FGT-CRY-03", "Kriptografi & IPsec VPN", "IPsec Phase-2 PFS ve algoritmaları güçlü");
    }
  }

  // ============================================================================
  // 8. LOGLAMA, SNMP, LDAP/RADIUS & HA (7.4 & 7.6)
  // ============================================================================
  const fazRaw = parseConfigSection(confText, "log fortianalyzer setting");
  const fazCloudRaw = parseConfigSection(confText, "log fortianalyzer-cloud setting");
  const syslogRaw = parseConfigSection(confText, "log syslogd setting");
  const syslog2Raw = parseConfigSection(confText, "log syslogd2 setting");
  const cloudLogRaw = parseConfigSection(confText, "log fortiguard setting");
  const diskLogRaw = parseConfigSection(confText, "log disk setting");
  const faz = parseKeyValues(fazRaw);
  const fazCloud = parseKeyValues(fazCloudRaw);
  const syslog = parseKeyValues(syslogRaw);
  const syslog2 = parseKeyValues(syslog2Raw);
  const cloudLog = parseKeyValues(cloudLogRaw);
  const diskLog = parseKeyValues(diskLogRaw);

  const hasRemoteLog =
    faz["status"] === "enable" ||
    fazCloud["status"] === "enable" ||
    syslog["status"] === "enable" ||
    syslog2["status"] === "enable" ||
    cloudLog["status"] === "enable";

  if (!hasRemoteLog) {
    addFinding({
      code: "FGT-LOG-01",
      category: "Loglama & SIEM Entegrasyonu",
      severity: diskLog["status"] === "enable" ? "LOW" : "MEDIUM",
      statusType: "MISSING",
      title: diskLog["status"] === "enable"
        ? "Sadece Yerel Disk Loglaması Aktif — Merkezi SIEM / Syslog / FortiAnalyzer Eksik"
        : "Merkezi Loglama (FortiAnalyzer / Syslog / FortiCloud) Yapılandırılmamış",
      description: "Cihaz üzerinde harici bir merkezi log/SIEM hedefi (OFTP TLS TCP/514 veya Reliable TLS Syslog TCP/6514) yapılandırılmamış.",
      currentConfig: `# Merkezi log sunucusu (log fortianalyzer / log syslogd) aktif değil (Eksik)`,
      expectedConfig: `config log syslogd setting\n    set status enable\n    set server "<SIEM_VEYA_SYSLOG_IP>"\n    set mode reliable\n    set port 6514\n    set enc-algorithm high\nend`,
      remediation: `# [EKLEME ADIMLARI - ŞİFRELİ MERKEZİ SYSLOG / SIEM ENTEGRASYONU]\nconfig log syslogd setting\n    set status enable\n    set server "<SIEM_VEYA_SYSLOG_IP>"\n    set mode reliable\n    set port 6514\n    set enc-algorithm high\nend`,
      diagnosticCli: `diagnose log test\nget log syslogd setting\nexecute log fortianalyzer test-connectivity`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS_7.6.8_Log_Reference.pdf & CIS Benchmark 7.1"
    });
  } else {
    addPassed("FGT-LOG-01", "Loglama & SIEM Entegrasyonu", "Merkezi log sunucusu aktif");
  }

  const snmpSysRaw = parseConfigSection(confText, "system snmp sysinfo");
  const snmpCommRaw = parseConfigSection(confText, "system snmp community");
  const snmpSys = parseKeyValues(snmpSysRaw);
  const snmpCommBlocks = parseEditBlocks(snmpCommRaw);
  if (snmpSys["status"] === "enable" && snmpCommBlocks.length > 0) {
    addFinding({
      code: "FGT-LOG-02",
      category: "Ağ ve İzleme Güvenliği (SNMP)",
      severity: "MEDIUM",
      statusType: "MISCONFIGURED",
      title: `Şifresiz SNMPv1/v2c Community Tanımlı (${snmpCommBlocks.length} Adet) — SNMPv3 (auth-priv) Kullanılmalı`,
      description: "SNMPv1 ve SNMPv2c 'community string' bilgisini ağ üzerinde düz metin (cleartext) olarak iletir. FortiOS 7.6.8'de eklenen IPsec egress shaping ve BIOS security level OID izlemeleri dahil tüm sorgular SNMPv3 (SHA256 + AES256) ile yapılmalıdır.",
      currentConfig: `config system snmp community\n    edit ${snmpCommBlocks[0].id}\n        set name "${snmpCommBlocks[0].settings["name"] || "public"}"\n    next\nend`,
      expectedConfig: `config system snmp community\n    purge\nend\nconfig system snmp user\n    edit "snmpv3_noc"\n        set security-level auth-priv\n        set auth-proto sha256\n        set priv-proto aes256\n    next\nend`,
      remediation: `# [DÜZELTME ADIMLARI - SNMPv1/v2c TEMİZLEME VE SNMPv3 KULLANICISI EKLEME]\nconfig system snmp community\n    purge\nend\nconfig system snmp user\n    edit "snmpv3_noc"\n        set security-level auth-priv\n        set auth-proto sha256\n        set auth-pwd <Auth_Parola>\n        set priv-proto aes256\n        set priv-pwd <Priv_Parola>\n    next\nend`,
      diagnosticCli: `show system snmp user`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-New_Features_Guide.pdf (s. 887-891 SNMPv3)"
    });
  } else {
    addPassed("FGT-LOG-02", "Ağ ve İzleme Güvenliği (SNMP)", "Güvensiz SNMPv1/v2c community kullanımı yok");
  }

  // Cleartext LDAP / RADIUS check (Best Practices 7.4 & 7.6)
  const ldapRaw = parseConfigSection(confText, "user ldap");
  const ldapBlocks = parseEditBlocks(ldapRaw);
  const insecureLdap = ldapBlocks.filter(l => !l.settings["secure"] || l.settings["secure"] === "disable");
  if (insecureLdap.length > 0) {
    addFinding({
      code: "FGT-AUTH-01",
      category: "Yönetim Güvenliği (Kimlik Doğrulama)",
      severity: "HIGH",
      statusType: "MISCONFIGURED",
      title: `Şifresiz (Cleartext TCP/389) LDAP Bağlantısı: ${insecureLdap.map(l => l.id).join(", ")} — LDAPS (TCP/636) Kullanılmalı`,
      description: "Active Directory / LDAP sunucu bağlantısında şifreleme ('set secure ldaps' ve 'set server-identity-check enable') aktif değil.",
      currentConfig: `config user ldap\n${insecureLdap.map(l => `    edit "${l.id}"\n        set server "${l.settings["server"] || "<AD_IP>"}"\n        set secure disable\n    next`).join("\n")}\nend`,
      expectedConfig: `config user ldap\n${insecureLdap.map(l => `    edit "${l.id}"\n        set secure ldaps\n        set port 636\n        set server-identity-check enable\n    next`).join("\n")}\nend`,
      remediation: `# [DÜZELTME ADIMLARI - LDAPS (TLS TCP/636) AKTİFLEŞTİRME]\nconfig user ldap\n${insecureLdap.map(l => `    edit "${l.id}"\n        set secure ldaps\n        set port 636\n        set ca-cert "<Kurumsal_AD_CA_Sertifikasi>"\n        set server-identity-check enable\n    next`).join("\n")}\nend`,
      diagnosticCli: `diagnose test authserver ldap "${insecureLdap[0].id}" <kullanici> <parola>`,
      reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.0-Best_Practices.pdf & FortiOS-7.6.0-Ports.pdf"
    });
  }

  const haRaw = parseConfigSection(confText, "system ha");
  const ha = parseKeyValues(haRaw);
  if (ha["mode"] && ha["mode"] !== "standalone") {
    if (ha["encryption"] !== "enable" || ha["authentication"] !== "enable") {
      addFinding({
        code: "FGT-HA-01",
        category: "Yüksek Erişilebilirlik (HA Hardening)",
        severity: "HIGH",
        statusType: "MISCONFIGURED",
        title: "HA (High Availability) Kümesinde Heartbeat Şifreleme ve Kimlik Doğrulama Kapalı",
        description: `Cihaz '${ha["mode"]}' HA modunda çalışıyor ancak Heartbeat paketlerinde (ETH 0x8890/0x8891/0x8893) şifreleme veya kimlik doğrulama aktif değil.`,
        currentConfig: `config system ha\n    set mode ${ha["mode"]}\n    set authentication ${ha["authentication"] || "disable"}\n    set encryption ${ha["encryption"] || "disable"}\nend`,
        expectedConfig: `config system ha\n    set mode ${ha["mode"]}\n    set authentication enable\n    set encryption enable\n    set hb-interval 2\n    set password <Guclu_HA_Parolasi>\nend`,
        remediation: `# [DÜZELTME ADIMLARI - HA HEARTBEAT ŞİFRELEME VE DOĞRULAMA AÇMA]\nconfig system ha\n    set authentication enable\n    set encryption enable\n    set hb-interval 2\n    set password <Guclu_HA_Parolasi>\nend`,
        diagnosticCli: `get system ha status\ndiagnose sys ha checksum cluster`,
        reference: "Fortinet Resmi Dokümanı (7.6): FortiOS-7.6.8-Administration_Guide.pdf (HA Hardening)"
      });
    } else {
      addPassed("FGT-HA-01", "Yüksek Erişilebilirlik (HA Hardening)", "HA Heartbeat şifrelemesi ve kimlik doğrulaması aktif");
    }
  }

  // ============================================================================
  // 9. FORTIOS 7.6 YENİ MİMARİ KONTROLLERİ (ZTNA, INLINE CASB, DLP, SD-WAN)
  // ============================================================================
  const sdwanRaw = parseConfigSection(confText, "system sdwan");
  const sdwanSettings = parseKeyValues(sdwanRaw);
  if (sdwanSettings["status"] === "enable") {
    const hasHealthCheck = /config\s+health-check/i.test(sdwanRaw) && /edit\s+/i.test(sdwanRaw);
    if (!hasHealthCheck) {
      addFinding({
        code: "FGT-SDW-01",
        category: "SD-WAN & SASE Mimarisi (7.4 / 7.6)",
        severity: "MEDIUM",
        statusType: "MISSING",
        title: "SD-WAN Aktif Ancak Performance SLA (health-check) Tanımlanmamış",
        description: "FortiOS 7.6 SD-WAN Service Bundle rehberine göre hat kalitesini (Latency, Jitter, Packet Loss) ölçmek ve otomatik hat yedeklemesi yapmak için 'config health-check' (FortiGuard SLA Database hedefleriyle) tanımlanmalıdır.",
        currentConfig: `config system sdwan\n    set status enable\n    # config health-check tanımlı değil (Eksik)\nend`,
        expectedConfig: `config system sdwan\n    set status enable\n    config health-check\n        edit "SLA_Internet_DNS"\n            set server "8.8.8.8" "1.1.1.1"\n            set protocol twamp\n            set members 0\n        next\n    end\nend`,
        remediation: `# [EKLEME ADIMLARI - SD-WAN PERFORMANCE SLA EKLEME]\nconfig system sdwan\n    config health-check\n        edit "SLA_Internet_Check"\n            set server "8.8.8.8" "1.1.1.1"\n            set protocol ping\n            set interval 1000\n            set probe-timeout 1000\n            set recoverytime 5\n            set members 0\n            config sla\n                edit 1\n                    set link-cost-factor latency jitter packet-loss\n                    set latency-threshold 150\n                    set jitter-threshold 30\n                    set packetloss-threshold 2\n                next\n            end\n        next\n    end\nend`,
        diagnosticCli: `diagnose sys sdwan health-check status\ndiagnose sys sdwan service4\ndiagnose sys sdwan member`,
        reference: "Fortinet Resmi Dokümanı (7.6): SD-WAN-7.6-Service_Bundle_Example_Guide.pdf & SD-WAN_with_FOS_FMG-7.6.x-New_Features.pdf"
      });
    } else {
      addPassed("FGT-SDW-01", "SD-WAN & SASE Mimarisi (7.4 / 7.6)", "SD-WAN Performance SLA (health-check) aktif");
    }
  }

  // ============================================================================
  // 10. 7.4 & 7.6 TROUBLESHOOTING CLI CHEAT SHEET (19 KATEGORİ TAM REFERANS)
  // ============================================================================
  const cliCheatSheet = [
    {
      section: "1. Debug Yönetimi (Enable / Disable Debugging)",
      commands: `diagnose debug reset\ndiagnose debug duration 0\ndiagnose debug console timestamp enable\ndiagnose debug enable\ndiagnose debug disable`
    },
    {
      section: "2. Sistem, Conserve Mode & Çökme Analizi (System & Crashlog)",
      commands: `get system status\nget system performance status\nexecute tac report\ndiagnose sys top 2 20\ndiagnose debug crashlog read\ndiagnose debug config-error-log read\ndiagnose hardware sysinfo memory\ndiagnose hardware sysinfo conserve\ndiagnose sys cmdb info`
    },
    {
      section: "3. Paket Akış Analizi & Sniffer (Debug Flow & Packet Capture)",
      commands: `diagnose debug reset\ndiagnose debug flow filter clear\ndiagnose debug flow filter addr <Hedef_IP>\ndiagnose debug flow show function-name enable\ndiagnose debug flow show iprope enable\ndiagnose debug console timestamp enable\ndiagnose debug flow trace start 100\ndiagnose debug enable\n\n# Canlı Paket Yakalama (Verbose 4: Arayüz + Paket Başlığı):\ndiagnose sniffer packet any "host <Hedef_IP> and port 443" 4 0 l`
    },
    {
      section: "4. Oturum Tablosu & NPU Fast-Path (Session Table & Hardware Acceleration 7.6.8)",
      commands: `diagnose sys session filter clear\ndiagnose sys session filter dst <Hedef_IP>\ndiagnose sys session filter dport 443\ndiagnose sys session list\ndiagnose firewall iprope list\n\n# NP7 / NP7Lite (SoC5) / NP6 Donanım Hızlandırma Kontrolü:\ndiagnose npu np7 pdq\ndiagnose npu np7 pmon\ndiagnose vpn tunnel npu-debug`
    },
    {
      section: "5. IPsec VPN & SSL/Agentless VPN (7.4 vs 7.6 Yeni Komutlar)",
      commands: `get vpn ipsec tunnel summary\ndiagnose vpn ike gateway list\ndiagnose vpn tunnel list\n\n# [YENİ 7.6]: Belirli Faz-1 veya Faz-2 Tünelini Sıfırlama & NPU Debug:\ndiagnose vpn ike gateway flush name <Tunel_Adi>\ndiagnose vpn tunnel flush <Faz2_Adi>\ndiagnose vpn tunnel npu-debug\n\n# Canlı IKE Müzakere Analizi:\ndiagnose vpn ike log filter rem-addr4 <Karsi_Peer_IP>\ndiagnose debug application ike -1\ndiagnose debug enable`
    },
    {
      section: "6. ZTNA & FortiClient EMS (7.4 vs 7.6 Yeni Multi-Tenant LLS-COMM Komutları)",
      commands: `diagnose endpoint fctems test-connectivity <EMS_Adi>\nexecute fctems verify <EMS_Adi>\ndiagnose test application fcnacd 2\ndiagnose firewall dynamic list\n\n# [7.4 ZTNA Kayıt Sorgulama]:\ndiagnose endpoint record list <IP>\ndiagnose endpoint wad-comm find-by ip-vdom <IP> <VDOM>\n\n# [YENİ 7.6 ZTNA EC-SHM & LLS-COMM Sorgulama]:\ndiagnose endpoint ec-shm list <IP> <MAC> <EMS_SN> <EMS_Tenant_ID>\ndiagnose endpoint lls-comm send ztna find-ip-vdom <IP> <VDOM>\ndiagnose wad worker policy list`
    },
    {
      section: "7. SD-WAN, BGP, OSPF & Routing (7.4 vs 7.6 Komut Farkları)",
      commands: `get router info routing-table all\nget router info routing-table database\nget router info bgp summary\nget router info ospf neighbor\n\n# SD-WAN Kontrol ve Veri Düzlemi (7.4.4+ ve 7.6.x):\ndiagnose sys sdwan health-check status\ndiagnose sys sdwan member\ndiagnose sys sdwan service4\ndiagnose sys sdwan service6\ndiagnose firewall proute list`
    },
    {
      section: "8. NGFW UTM, IPS, WAD, DLP & Inline CASB",
      commands: `diagnose test application ipsmonitor 1\ndiagnose test application ipsmonitor 99\ndiagnose test application wad 1000\ndiagnose test application wad 2\ndiagnose webfilter fortiguard statistics\ndiagnose debug rating\ndiagnose autoupdate versions`
    },
    {
      section: "9. HA (High Availability), FortiSwitch & FortiAP",
      commands: `get system ha status\ndiagnose sys ha checksum cluster\ndiagnose sys ha history read\nexecute ha manage <index> <admin_user>\n\n# FortiSwitch & FortiAP:\nexecute switch-controller get-conn-status\ndiagnose switch-controller switch-info mac-table\ndiagnose wireless-controller wlac -c wtp`
    }
  ];

  // ============================================================================
  // AĞIRLIKLI UYUMLULUK SKORU (NORMALIZED WEIGHTED COMPLIANCE SCORE: 0-100)
  // ============================================================================
  const CONTROL_WEIGHTS = {
    "FGT-CVE-01": 14,
    "FGT-SSL-01": 9,
    "FGT-SSL-02": 10,
    "FGT-SSL-03": 6,
    "FGT-SSL-04": 6,
    "FGT-SSL-05": 3,
    "FGT-ADM-01": 5,
    "FGT-ADM-02": 3,
    "FGT-ADM-03": 4,
    "FGT-ADM-04": 7,
    "FGT-ADM-05": 2,
    "FGT-ADM-06": 4,
    "FGT-ADM-07": 6,
    "FGT-ADM-08": 4,
    "FGT-ADM-09": 9,
    "FGT-ADM-10": 6,
    "FGT-ADM-11": 4,
    "FGT-ADM-12": 4,
    "FGT-NET-01": 14,
    "FGT-NET-02": 8,
    "FGT-NET-03": 6,
    "FGT-NET-04": 6,
    "FGT-NET-05": 5,
    "FGT-NET-06": 3,
    "FGT-HW-01": 5,
    "FGT-HW-02": 5,
    "FGT-HW-03": 3,
    "FGT-POL-01": 12,
    "FGT-POL-02": 8,
    "FGT-POL-03": 5,
    "FGT-POL-04": 2,
    "FGT-POL-05": 7,
    "FGT-CRY-01": 7,
    "FGT-CRY-02": 3,
    "FGT-CRY-03": 5,
    "FGT-LOG-01": 5,
    "FGT-LOG-02": 4,
    "FGT-AUTH-01": 6,
    "FGT-HA-01": 6,
    "FGT-SDW-01": 4
  };
  const SEVERITY_FALLBACK = { CRITICAL: 12, HIGH: 7, MEDIUM: 4, LOW: 2 };

  const earnedWeight = passedControls.reduce(
    (sum, p) => sum + (CONTROL_WEIGHTS[p.id] || 6),
    0
  );
  const failedWeight = findings.reduce(
    (sum, f) => sum + (CONTROL_WEIGHTS[f.id] || SEVERITY_FALLBACK[f.severity] || 4),
    0
  );
  const totalEvaluatedWeight = earnedWeight + failedWeight;
  const rawPercentage = totalEvaluatedWeight > 0
    ? Math.round((earnedWeight / totalEvaluatedWeight) * 100)
    : 100;
  const score = findings.length === 0 ? 100 : Math.max(8, Math.min(99, rawPercentage));

  const counts = {
    CRITICAL: findings.filter(f => f.severity === "CRITICAL").length,
    HIGH: findings.filter(f => f.severity === "HIGH").length,
    MEDIUM: findings.filter(f => f.severity === "MEDIUM").length,
    LOW: findings.filter(f => f.severity === "LOW").length,
    MISSING: findings.filter(f => f.statusType === "MISSING").length,
    MISCONFIGURED: findings.filter(f => f.statusType === "MISCONFIGURED").length,
    PASSED: passedControls.length
  };

  const upgradeAdvisor = buildUpgradeAdvisor({
    model,
    version,
    build,
    is76Branch,
    is2GbModel
  });

  return {
    metadata: {
      hostname,
      model,
      version,
      build,
      branch: is76Branch ? "7.6" : "7.4",
      targetProfile: is76Branch ? "7.6" : "7.4",
      is2GbModel,
      vdomEnabled,
      analyzedAt: new Date().toISOString(),
      interfacesCount: intfBlocks.length,
      policiesCount: fwPolicies.length,
      adminsCount: adminBlocks.length,
      vpnTunnelsCount: phase1Blocks.length
    },
    score,
    counts,
    findings,
    passedControls,
    upgradeAdvisor,
    cliCheatSheet
  };
}

function buildUpgradeAdvisor({ model, version, build, is76Branch, is2GbModel }) {
  const upperModel = String(model || "FGT").toUpperCase();
  const verStr = String(version || "7.4.0");
  const isGSeries = /FGT\d+G|FG-\d+G|50G|70G|90G|91G|120G|121G|200G|201G|900G/i.test(upperModel);
  const isESeriesOrOlder = /FGT\d+[CDE]|FG-\d+[CDE]/i.test(upperModel);

  let hardwareGeneration = "F-Serisi (SoC4 / NP6XLite / NP7 Donanım Mimarisi)";
  if (isGSeries) {
    hardwareGeneration = "G-Serisi Yeni Nesil (SP5 / NP7Lite / NP7 + CP10 Donanım Mimarisi)";
  } else if (isESeriesOrOlder) {
    hardwareGeneration = "E-Serisi veya Öncesi (Eski Nesil ASIC — Donanım Yenileme Öncelikli)";
  }

  const ramCategory = is2GbModel
    ? "2 GB RAM / Giriş Seviyesi Sınıfı (7.6 Sürümünde SSL-VPN ve Proxy Kısıtlı)"
    : "4 GB+ RAM Kurumsal Sınıf (Tam UTM, Deep Inspection, ZTNA ve Inline CASB Uygun)";

  // 1. In-Place OS Upgrade Options (Same Hardware)
  const isAlready74Latest = verStr.startsWith("7.4.") && parseInt(verStr.split(".")[2] || "0", 10) >= 13;
  const isAlready76Latest = verStr.startsWith("7.6.") && parseInt(verStr.split(".")[2] || "0", 10) >= 8;

  const osUpgradeOptions = [
    {
      id: "OS-OPT-74",
      badge: "KARARLI ÜRETİM (MATURE)",
      title: `Aynı Cihazda (${upperModel}) FortiOS 7.4.13 GA (Mature) Sürümüne Yükseltme`,
      targetVersion: "FortiOS 7.4.13 GA (Build 2890+)",
      currentStatus: is76Branch
        ? `Cihaz şu an v${verStr} (7.6 dalı) üzerinde çalışıyor. 7.4 dalına geri dönüş (downgrade) konfigürasyon kaybına yol açabileceği için 7.6.8'de kalınması önerilir.`
        : isAlready74Latest
          ? `✓ Cihazınız zaten FortiOS 7.4 dalının güncel kararlı sürümünde (v${verStr}).`
          : `Mevcut v${verStr} sürümünden FortiOS 7.4.13 GA sürümüne kademeli yükseltme önerilir.`,
      recommendedPath: is76Branch
        ? `Downgrade önerilmez -> Doğrudan FortiOS 7.6.8 GA sürümüne ilerleyin`
        : `v${verStr} ➔ v7.4.6 ➔ v7.4.9 ➔ v7.4.13 GA (Fortinet Destekli Upgrade Path)`,
      pros: [
        "Fortinet tarafından 'Mature' (Olgunlaşmış) olarak işaretlenen en kararlı uzun vadeli üretim (Production) sürümüdür.",
        "2024–2026 dönemindeki tüm kritik PSIRT zafiyetlerini (CVE-2024-21762, CVE-2024-55591, CVE-2025-24472, CVE-2026-21643) kapatır.",
        "4 GB+ RAM'li cihazlarda mevcut SSL-VPN yapılandırmasını anında silmeden IPsec IKEv2 veya ZTNA'ya planlı geçiş süresi tanır.",
        "2 GB RAM'li cihazlarda (40F/60F/61F) bellek ayak izi 7.6'ya göre daha düşüktür; Conserve Mode riski daha azdır."
      ],
      cons: [
        "FortiOS 7.6 ile gelen Local-In Virtual Patching ('set virtual-patch enable') ve varsayılan PBKDF2 ('ENC PB2...') admin parola özetleme özelliklerini içermez.",
        "Yeni nesil G-serisi (SP5 / NP7Lite / CP10) donanımlarda 7.6.8 kadar gelişmiş NPU/QoS optimizasyonu sunmaz.",
        "7.6'daki genişletilmiş ZTNA ('ec-shm' / 'lls-comm') ve Inline CASB SaaS kiracı denetimi yetenekleri sınırlıdır."
      ],
      preCheckCli: `execute backup config flash "pre-upgrade-${upperModel}-${verStr}"\nget system status\ndiagnose sys flash list\ndiagnose debug config-error-log read`
    },
    {
      id: "OS-OPT-76",
      badge: is2GbModel ? "DİKKATLİ GEÇİŞ (2GB KISITI)" : "YENİ NESİL ÖZELLİK & GÜVENLİK (7.6 GA)",
      title: `Aynı Cihazda (${upperModel}) FortiOS 7.6.8 GA Sürümüne Yükseltme`,
      targetVersion: "FortiOS 7.6.8 GA (Build 3692+)",
      currentStatus: isAlready76Latest
        ? `✓ Cihazınız zaten FortiOS 7.6 dalının en güncel sürümünde (v${verStr}).`
        : is2GbModel
          ? `⚠️ ${upperModel} modelinde 7.6.8'e geçişte SSL-VPN (Tunnel & Web/Agentless) tamamen kaldırılır. Yalnızca IPsec/ZTNA dönüşümü hazırsa yükseltin.`
          : `Mevcut v${verStr} sürümünden FortiOS 7.6.8 GA yeni nesil güvenlik sürümüne yükseltme yapılabilir.`,
      recommendedPath: is76Branch
        ? `v${verStr} ➔ v7.6.3 ➔ v7.6.6 ➔ v7.6.8 GA`
        : `v${verStr} ➔ v7.4.9+ ➔ v7.6.3 ➔ v7.6.6 ➔ v7.6.8 GA`,
      pros: [
        "SSL-VPN Tunnel Mode saldırı yüzeyini tamamen kapatır; TCP 443/11443 üzerinden çalışan IPsec IKEv2 ('set transport udp-fallback-tcp') ve ZTNA 7.6.3 mimarisini sunar.",
        "Yönetici parolalarında PBKDF2 ('ENC PB2...') kriptografik özetleme, zorunlu 12+ karakter parola politikası ve varsayılan 'allow-traffic-redirect disable' koruması sağlar.",
        "Yönetim portlarını sıfırıncı gün zafiyetlerine karşı koruyan Local-In Virtual Patching ('set virtual-patch enable') ve varsayılan Tor/Malicious ISDB engellemesi içerir.",
        "Inline CASB (SaaS Uygulama/Kiracı Kontrolü), gelişmiş DLP ve NP7/NP7Lite ('diagnose vpn tunnel npu-debug', 'policing QoS') donanım hızlandırmasını tam kapasite çalıştırır."
      ],
      cons: [
        "SSL-VPN Tunnel Mode tüm cihazlarda tamamen kaldırılmıştır! Yükseltme öncesi FortiClient kullanıcıları IPsec IKEv2 veya ZTNA'ya geçirilmezse uzak bağlantılar kopar.",
        "Giriş seviyesi / 2 GB RAM modellerde (40F, 60F, 61F, 50G, 70G, 90G, 91G) Agentless VPN (eski Web Mode) de kaldırılmıştır.",
        "2 GB RAM'li F-serisi cihazlarda WAD / IPS / Proxy süreçlerinin bellek tüketimi 7.6'da arttığı için yoğun trafikte Conserve Mode riski oluşturabilir.",
        "SD-WAN altında 'set app-monitor enable' (APM) açılırsa ilgili firewall kuralında NPU donanım hızlandırması devre dışı kalır."
      ],
      preCheckCli: `# 7.6 Yükseltmesi Öncesi SSL-VPN Bağımlılık Kontrolü:\nshow vpn ssl settings\nshow vpn ssl web portal\ndiagnose sys top-mem 15\nexecute backup config flash "pre-768-upgrade"`
    }
  ];

  // 2. Hardware Upgrade Recommendation (New Fortinet Model Comparison)
  let hwRec;
  if (/40F|60E|60F|61E|61F|50G|70F/i.test(upperModel)) {
    hwRec = {
      currentModel: upperModel,
      currentSpecs: "SoC4 ASIC | 2 GB RAM | 1 GE RJ45 Portlar | ~700 Mbps Threat Protection | ~650 Mbps SSL Inspection",
      recommendedModels: "FortiGate 70G veya FortiGate 90G (Önerilen Kurumsal Sıçrama)",
      targetSpecs: "Fortinet SP5 (5. Nesil) ASIC | 4 GB (70G) / 8 GB RAM (90G) | 2x 10GE RJ45/SFP+ + 2.5GE Portlar | 2.2 Gbps Threat Protection (90G) | 2.5 Gbps SSL Deep Inspection",
      whyUpgrade: `${upperModel} modeli 2 GB RAM sınırı nedeniyle FortiOS 7.4/7.6 sürümlerinde ZTNA, SSL Deep Inspection ve yoğun WAD proxy işlemlerinde bellek darboğazına (Conserve Mode) girmeye açıktır. FortiGate 90G (8 GB RAM + SP5 ASIC) ile hem 2 GB RAM kısıtlarından tamamen kurtulursunuz hem de 10GE arayüz ve 3.5 kat daha yüksek SSL Deep Inspection performansı elde edersiniz.`,
      pros: [
        "2 GB RAM darboğazından 8 GB RAM'e (90G) geçiş sayesinde FortiOS 7.6'da Conserve Mode riskini ortadan kaldırır.",
        "Yeni nesil 7nm SP5 ASIC ile Threat Protection hızı ~700 Mbps'den 2.2 Gbps'ye, SSL Deep Inspection hızı 2.5 Gbps'ye çıkar.",
        "2 adet 10GE (RJ45/SFP+ paylaşımlı) ve 2.5GE portlar sayesinde Wi-Fi 7 (FortiAP) ve yüksek hızlı fiber WAN hatlarını darboğazsız sonlandırır.",
        "IPsec VPN performansı 6.5 Gbps'den 25 Gbps'ye (90G) yükselir; SSL-VPN yerine IKEv2 TCP geçişinde donanım hızlandırma sağlar."
      ],
      cons: [
        "Yeni donanım satın alma (CapEx) ve mevcut FortiGuard UTM/ATP lisanslarının yeni cihaza taşınması veya yenilenmesi maliyeti vardır.",
        "FortiGate 90G/70G serisinde de FortiOS 7.6 politikası gereği SSL-VPN yerine IPsec IKEv2 veya ZTNA mimarisi kullanılmalıdır.",
        "Arayüz isimlendirmeleri (örn. wan1/internal yerine port1..port8/x1/x2) farklı olduğu için konfigürasyon geçişinde FortiConverter veya arayüz eşlemesi gerekir."
      ]
    };
  } else if (/80E|80F|81E|81F|90E/i.test(upperModel)) {
    hwRec = {
      currentModel: upperModel,
      currentSpecs: "SoC4 ASIC | 4 GB RAM | 1 GE Portlar | ~900 Mbps Threat Protection | ~715 Mbps SSL Inspection",
      recommendedModels: "FortiGate 90G veya FortiGate 120G",
      targetSpecs: "SP5 ASIC | 8 GB RAM | 10GE SFP+ & 2.5GE Portlar | 2.2 Gbps (90G) – 3.1 Gbps (120G) Threat Protection | 2.5 – 3.0 Gbps SSL Inspection",
      whyUpgrade: `${upperModel} cihazınız 4 GB RAM ile orta ölçekli yükleri kaldırsa da 1 GE portlarla sınırlıdır ve SoC4 ASIC mimarisi TLS 1.3 Deep Inspection ile Inline CASB yüklerinde sınırlarına ulaşır. FortiGate 90G (Masaüstü/Şube) veya 120G (1U Rackmount, Çift Güç Kaynağı) modeline geçiş 3 kata kadar NGFW/SSL performansı sağlar.`,
      pros: [
        "SP5 ASIC sayesinde TLS 1.3 Deep Inspection ve IPS/Application Control performansında ~3 kat artış (3.1 Gbps Threat Protection - 120G).",
        "10GE SFP+ fiber/bakır uplink portları ile omurga switch (FortiSwitch) bağlantısında 1 Gbps darboğazını aşar.",
        "FortiGate 120G modelinde 1U kabinet tipi kasa ve yerleşik yedekli güç kaynağı (Dual PSU) ile yüksek fiziksel süreklilik.",
        "FortiOS 7.6 Inline CASB, DLP ve ZTNA Access Proxy özelliklerini yüksek oturum kapasitesiyle çalıştırır."
      ],
      cons: [
        "Donanım yenileme (CapEx) ve lisanslama bütçesi gerektirir.",
        "7.6 sürümünde SSL-VPN yerine IPsec IKEv2 / ZTNA dönüşümü planlanmalıdır."
      ]
    };
  } else if (/90G|91G/i.test(upperModel)) {
    hwRec = {
      currentModel: upperModel,
      currentSpecs: "SP5 ASIC (Güncel G-Serisi) | 8 GB RAM | 2x 10GE + 6x 2.5GE | 2.2 Gbps Threat Protection | 2.5 Gbps SSL Inspection",
      recommendedModels: "Mevcut Donanım Günceldir (Büyüme İhtiyacında: FortiGate 120G veya FortiGate 200G)",
      targetSpecs: "FortiGate 200G: NP7 + CP10 ASIC | 16 GB RAM Sınıfı | 8x 10GE SFP+ + 8x 5GE | 6 Gbps Threat Protection | 7 Gbps SSL Inspection",
      whyUpgrade: `Cihazınız (${upperModel}) Fortinet'in en güncel G-Serisi SP5 ASIC mimarisine sahiptir; dolayısıyla acil bir donanım değişimine ihtiyacınız yoktur! Ancak kampüs/veri merkezi trafiğiniz 2.2 Gbps Threat Protection sınırını aşıyorsa veya yedekli güç kaynağı (Dual PSU) + çoklu 10GE SFP+ port gerekiyorsa bir üst segment olan FortiGate 120G veya NP7+CP10 tabanlı FortiGate 200G'ye çıkabilirsiniz.`,
      pros: [
        "Mevcut FGT-90G/91G donanımınız FortiOS 7.4.13 ve 7.6.8 için zaten yeni nesil SP5 hızlandırma desteğine sahiptir.",
        "Üst model olan FortiGate 200G'ye geçilirse bağımsız NP7 ağ işlemcisi + CP10 içerik işlemcisi ile 6 Gbps Threat Protection ve 7 Gbps SSL Inspection kapasitesine ulaşılır.",
        "120G/200G modellerinde 1U Rackmount mimari ve Dual PSU (Çift Güç Kaynağı) donanım yedekliliği bulunur."
      ],
      cons: [
        "Mevcut 90G cihazınız zaten son nesil olduğu için kapasite aşımı yoksa donanım değiştirmek gereksiz maliyet (CapEx) yaratacaktır.",
        "90G/91G modellerinde FortiOS 7.6.3+ sürümünde SSL-VPN (Tunnel ve Agentless) tamamen kaldırıldığı için IPsec IKEv2 TCP veya ZTNA kullanılması zorunludur."
      ]
    };
  } else if (/100D|100E|100F|101E|101F/i.test(upperModel)) {
    hwRec = {
      currentModel: upperModel,
      currentSpecs: "SoC4 ASIC (100F) / NP6 (100E) | 4 GB – 8 GB RAM | 2x 10GE SFP+ | 1 Gbps Threat Protection | 1 Gbps SSL Deep Inspection",
      recommendedModels: "FortiGate 120G (SP5 ASIC) veya FortiGate 200G (NP7 + CP10 ASIC — Önerilen)",
      targetSpecs: "FortiGate 120G: 3.1 Gbps Threat Protection, 3 Gbps SSL Inspection | FortiGate 200G: NP7 + CP10 ASIC, 6 Gbps Threat Protection, 7 Gbps SSL Inspection, 8x 10GE SFP+ + 8x 5GE",
      whyUpgrade: `${upperModel} kurumsal ağlarda çok yaygın olsa da 1 Gbps Threat Protection ve 1 Gbps SSL Deep Inspection kapasitesi güncel 1 Gbps+ simetrik Metro Ethernet / SD-WAN ve yoğun TLS 1.3 şifreli SaaS trafiğinde darboğaz oluşturmaktadır. FortiGate 120G'ye geçiş performansı 3 katına (3.1 Gbps), FortiGate 200G'ye geçiş ise 6 katına (6 Gbps Threat Protection + NP7/CP10 donanım hızlandırma) çıkarır.`,
      pros: [
        "SSL Deep Inspection kapasitesi 1 Gbps'den 3 Gbps'ye (120G) veya 7 Gbps'ye (200G) sıçrar; şifreli trafik incelenirken yaşanan gecikmeler biter.",
        "FortiGate 200G'deki veri merkezi sınıfı NP7 + CP10 işlemciler, filigranlı DDoS, elephant flow ve IPsec VPN trafiğini CPU'yu yormadan donanımda işler.",
        "FortiOS 7.6 Inline CASB, DLP, ZTNA ve SD-WAN SLA işlemlerinde çok daha yüksek eşzamanlı oturum (Concurrent Session) ve yeni oturum kapasitesi sunar.",
        "8x 10GE SFP+ ve 8x 5GE RJ45 portlar (200G) ile ek switch yatırımı olmadan yüksek hızlı sunucu ve omurga bağlantısı sağlar."
      ],
      cons: [
        "Yeni nesil G-serisi donanım ve UTM/Enterprise lisans yenileme maliyeti (CapEx/OpEx) gerektirir.",
        "100F üzerindeki mevcut konfigürasyonun 120G/200G port yapısına aktarılması için planlı bakım penceresi gerekir."
      ]
    };
  } else if (/120G|121G|200G|201G/i.test(upperModel)) {
    hwRec = {
      currentModel: upperModel,
      currentSpecs: "G-Serisi Yeni Nesil (SP5 / NP7 + CP10 ASIC) | 10GE SFP+ & 5GE Portlar | 3.1 – 6.0 Gbps Threat Protection",
      recommendedModels: "Mevcut Donanım En Güncel G-Serisidir (Veri Merkezi Büyümesinde: FortiGate 400F / 600F / 900G)",
      targetSpecs: "FortiGate 600F / 900G: NP7 + CP9/CP10 ASIC | 4x 25GE SFP28 + 10GE Portlar | 10.5 – 20 Gbps Threat Protection | 8 – 16 Gbps SSL Inspection",
      whyUpgrade: `Cihazınız (${upperModel}) Fortinet'in en yeni G-serisi donanım ailesindendir ve FortiOS 7.6.8 için tam donanım hızlandırma (NP7/SP5/CP10) desteğine sahiptir. Yalnızca veri merkezi omurgasında 25GE SFP28 arayüzlere veya 10+ Gbps üzerinde Threat Protection kapasitesine ihtiyaç duyulursa FortiGate 600F veya 900G serisine geçiş değerlendirilmelidir.`,
      pros: [
        "Mevcut G-serisi cihazınız FortiOS 7.6.8'in tüm yeni özelliklerini (Inline CASB, DLP, ZTNA, IKEv2 TCP, NP7 QoS Policing) donanımsal olarak destekler.",
        "Üst segment 600F/900G serisine geçildiğinde 25GE SFP28 veri merkezi portları ve 20 Gbps'ye varan Threat Protection elde edilir."
      ],
      cons: [
        "Kapasite artışı ihtiyacı yoksa mevcut G-serisi cihazı değiştirmek maliyet açısından gerekli değildir; yazılımı 7.4.13 veya 7.6.8'de tutmak yeterlidir."
      ]
    };
  } else {
    hwRec = {
      currentModel: upperModel,
      currentSpecs: "Mevcut Kurumsal FortiGate Platformu (F/E Serisi veya VM)",
      recommendedModels: "FortiGate 200G (Orta-Büyük Ölçek) veya FortiGate 600F / 900G (Veri Merkezi / Kampüs)",
      targetSpecs: "NP7 + CP10 Yeni Nesil ASIC | 5GE / 10GE SFP+ / 25GE SFP28 Arayüzler | 6 Gbps – 20 Gbps Threat Protection | 7 Gbps – 16 Gbps SSL Deep Inspection",
      whyUpgrade: `${upperModel} platformundan yeni nesil NP7 + CP10 tabanlı G-serisi (FortiGate 200G / 900G) donanımlara geçiş; özellikle TLS 1.3 Deep Inspection, ZTNA Access Proxy, Inline CASB ve yüksek hızlı IPsec IKEv2 tünellerinde donanım hızlandırma kapasitesini katlayarak artırır.`,
      pros: [
        "NP7 ve CP10 ASIC mimarisi ile 7.6.8 donanım hızlandırma özelliklerinden ('diagnose vpn tunnel npu-debug', 'default-qos-type policing') tam yararlanma.",
        "Yüksek RAM kapasitesi ile FortiOS 7.6 WAD/IPS/CASB/DLP süreçlerinde yüksek kararlılık.",
        "10GE ve 25GE port yoğunluğu ile modern kampüs ve veri merkezi topolojilerine tam uyum."
      ],
      cons: [
        "Donanım ve lisans geçiş maliyeti (CapEx) ile bakım penceresi planlaması gerektirir."
      ]
    };
  }

  return {
    currentSummary: {
      model: upperModel,
      version: verStr,
      build: String(build || "unknown"),
      hardwareGeneration,
      ramCategory
    },
    osUpgradeOptions,
    hardwareUpgradeRecommendation: hwRec
  };
}

export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const { configText, targetProfile } = body;

    if (!configText || typeof configText !== "string" || configText.trim().length < 25) {
      return new Response(
        JSON.stringify({ error: "Lütfen geçerli bir FortiGate konfigürasyon (.conf) dosyası yükleyiniz." }),
        { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } }
      );
    }

    const report = analyzeFortiGateConfig(configText, targetProfile || "auto");

    return new Response(
      JSON.stringify({
        preview: false,
        ...report
      }),
      { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "Konfigürasyon dosyası incelenirken bir hata oluştu." }),
      { status: 500, headers: { "Content-Type": "application/json; charset=utf-8" } }
    );
  }
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    if (request.method === "POST" && (url.pathname.endsWith("/api/analyze") || url.pathname === "/")) {
      const response = await onRequestPost({ request, env, ctx });
      const newHeaders = new Headers(response.headers);
      for (const [k, v] of Object.entries(CORS_HEADERS)) {
        newHeaders.set(k, v);
      }
      return new Response(response.body, { status: response.status, headers: newHeaders });
    }

    if (env && env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response(
      JSON.stringify({ status: "ONLINE", engine: "FortiOS 7.4 & 7.6 Hardening & Compliance Engine" }),
      { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS } }
    );
  }
};
