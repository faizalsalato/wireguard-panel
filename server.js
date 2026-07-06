/**
 * WireGuard Panel – server.js
 * Melhorado: validação, segurança, persistência, rate limit,
 * sanitização de input, logging estruturado e gestão de erros robusta.
 */

"use strict";

const express  = require("express");
const { exec } = require("child_process");
const multer   = require("multer");
const fs       = require("fs");
const path     = require("path");

// ─────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────
const PORT    = process.env.PORT    || 4000;
const WG_DIR  = process.env.WG_DIR  || "/etc/wireguard";
const STATE_FILE = path.join(WG_DIR, ".wg-panel-state.json");

// Limite de tamanho do ficheiro de config (1 MB)
const MAX_UPLOAD_SIZE = 1 * 1024 * 1024;

// Timeout para comandos wg-quick (ms)
const WG_CMD_TIMEOUT = 15_000;

// ─────────────────────────────────────────────
// Logger simples com timestamp
// ─────────────────────────────────────────────
const log = {
  info : (...a) => console.log (`[${ts()}] INFO `, ...a),
  warn : (...a) => console.warn(`[${ts()}] WARN `, ...a),
  error: (...a) => console.error(`[${ts()}] ERROR`, ...a),
};
function ts() { return new Date().toISOString(); }

// ─────────────────────────────────────────────
// Persistência de estado
// ─────────────────────────────────────────────
function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = fs.readFileSync(STATE_FILE, "utf8");
      return JSON.parse(raw);
    }
  } catch (e) {
    log.warn("Falha ao carregar estado:", e.message);
  }
  return { currentInterface: null };
}

function saveState(state) {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf8");
  } catch (e) {
    log.warn("Falha ao guardar estado:", e.message);
  }
}

// ─────────────────────────────────────────────
// Estado da aplicação
// ─────────────────────────────────────────────
let state = loadState();

// ─────────────────────────────────────────────
// Validação / sanitização de nomes de interface
// ─────────────────────────────────────────────
const IFACE_RE = /^[a-zA-Z0-9_-]{1,15}$/;

/**
 * Valida e sanitiza o nome de uma interface WireGuard.
 * Aceita "wg0" ou "wg0.conf" (remove a extensão automaticamente).
 * Rejeita qualquer coisa suspeita.
 */
function sanitizeIface(raw) {
  if (!raw || typeof raw !== "string") return null;
  const name = raw.replace(/\.conf$/i, "").trim();
  return IFACE_RE.test(name) ? name : null;
}

// ─────────────────────────────────────────────
// Wrapper seguro para exec com timeout
// ─────────────────────────────────────────────
function runCmd(cmd, timeoutMs = WG_CMD_TIMEOUT) {
  return new Promise((resolve, reject) => {
    log.info("CMD:", cmd);
    const child = exec(cmd, { timeout: timeoutMs }, (err, stdout, stderr) => {
      if (err) {
        log.error("CMD falhou:", stderr || err.message);
        return reject(new Error(stderr?.trim() || err.message));
      }
      resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
    });
    // Garante kill se o processo pai morrer
    process.on("exit", () => child.kill());
  });
}

// ─────────────────────────────────────────────
// Setup de directórios
// ─────────────────────────────────────────────
if (!fs.existsSync(WG_DIR)) {
  fs.mkdirSync(WG_DIR, { recursive: true });
  log.info("Criado directório WireGuard:", WG_DIR);
}

// ─────────────────────────────────────────────
// Multer – upload seguro de configs
// ─────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: WG_DIR,
  filename: (req, file, cb) => {
    // Garante nome seguro: só nome base, sem path traversal
    const safe = path.basename(file.originalname).replace(/[^a-zA-Z0-9_.-]/g, "_");
    // Força extensão .conf
    const name = safe.endsWith(".conf") ? safe : safe + ".conf";
    cb(null, name);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_SIZE },
  fileFilter: (req, file, cb) => {
    // Aceita só .conf
    if (!file.originalname.match(/\.conf$/i)) {
      return cb(new Error("Apenas ficheiros .conf são aceites"), false);
    }
    cb(null, true);
  },
});

// ─────────────────────────────────────────────
// App Express
// ─────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.static("public"));

// Rate limiter simples (sem dependência externa)
const rateLimitMap = new Map();
function rateLimit(windowMs = 60_000, max = 20) {
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const entry = rateLimitMap.get(key) || { count: 0, start: now };

    if (now - entry.start > windowMs) {
      entry.count = 0;
      entry.start = now;
    }
    entry.count++;
    rateLimitMap.set(key, entry);

    if (entry.count > max) {
      return res.status(429).json({ error: "Demasiadas requisições. Aguarde." });
    }
    next();
  };
}
app.use(rateLimit());

// ─────────────────────────────────────────────
// Rotas
// ─────────────────────────────────────────────

// ── Listar configs ────────────────────────────
app.get("/configs", (req, res) => {
  try {
    const files = fs.readdirSync(WG_DIR)
      .filter(f => f.endsWith(".conf") && !f.startsWith("."))
      .sort();
    res.json(files);
  } catch (e) {
    log.error("Listar configs:", e.message);
    res.status(500).json({ error: "Falha ao listar configurações" });
  }
});

// ── Verificar IP Público ───────────────────────────────
app.get("/my-ip", async (req, res) => {
  try {
    // A flag -4 obriga o curl a usar apenas IPv4
    const { stdout } = await runCmd("curl -4 -s -m 5 ifconfig.me");
    res.json({ ip: stdout.trim() });
  } catch (e) {
    log.error("Erro ao obter IP:", e.message);
    res.status(500).json({ error: "Falha" });
  }
});

// ── Upload config ─────────────────────────────
// ── Upload config com injeção de PrivateKey ─────────────────────────────
app.post("/upload", (req, res) => {
  upload.single("config")(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: `Ficheiro demasiado grande (máx ${MAX_UPLOAD_SIZE / 1024} KB)` });
      }
      return res.status(400).json({ error: err.message });
    }
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ error: "Nenhum ficheiro enviado" });
    }

    // Injeção da PrivateKey (se enviada no form)
    if (req.body.privateKey) {
      const filePath = req.file.path;
      let content = fs.readFileSync(filePath, "utf8");
      const pk = req.body.privateKey.trim();

      if (content.match(/^PrivateKey\s*=/m)) {
        // Substitui a existente
        content = content.replace(/^PrivateKey\s*=.*$/m, `PrivateKey = ${pk}`);
      } else {
        // Insere logo abaixo de [Interface]
        content = content.replace(/(\[Interface\])/i, `$1\nPrivateKey = ${pk}`);
      }
      
      fs.writeFileSync(filePath, content, "utf8");
      log.info(`PrivateKey injetada no ficheiro: ${req.file.filename}`);
    }

    log.info("Config carregada:", req.file.filename);
    res.json({ ok: true, file: req.file.filename });
  });
});

// ── Conectar ──────────────────────────────────
// ── Conectar ──────────────────────────────────
app.post("/connect/:name", async (req, res) => {
  const iface = sanitizeIface(req.params.name);
  if (!iface) {
    return res.status(400).json({ error: "Nome de interface inválido" });
  }

  // Verifica se o ficheiro existe
  const confPath = path.join(WG_DIR, `${iface}.conf`);
  if (!fs.existsSync(confPath)) {
    return res.status(404).json({ error: `Config não encontrada: ${iface}.conf` });
  }

  // --- VALIDAÇÃO DE SEGURANÇA: Verifica se tem chave e rotas ---
  const content = fs.readFileSync(confPath, "utf8");
  if (!content.match(/^PrivateKey\s*=/m)) {
    return res.status(400).json({ error: "Falta a PrivateKey. Faça upload novamente com a chave." });
  }
  if (!content.includes("PostUp = ip route add") && !content.includes("PostUp = ip rule add")) {
    return res.status(400).json({ error: "Faltam as rotas. Utilize o painel para atualizar as rotas primeiro." });
  }
  // -------------------------------------------------------------

  // Já está ligado a esta interface
  if (state.currentInterface === iface) {
    return res.json({ status: "já conectado", interface: iface });
  }

  try {
    // Desligar a interface atual primeiro (se existir)
    if (state.currentInterface) {
      try {
        await runCmd(`wg-quick down ${state.currentInterface}`);
        log.info("Desligado:", state.currentInterface);
      } catch (e) {
        log.warn(`Falha ao desligar ${state.currentInterface}:`, e.message);
      }
    }

    await runCmd(`wg-quick up ${iface}`);

    state.currentInterface = iface;
    saveState(state);
    log.info("Conectado:", iface);
    res.json({ status: "conectado", interface: iface });

  } catch (e) {
    state.currentInterface = null;
    saveState(state);
    res.status(500).json({ error: e.message });
  }
});

// ── Desconectar ───────────────────────────────
app.post("/disconnect", async (req, res) => {
  if (!state.currentInterface) {
    return res.json({ status: "sem conexão ativa" });
  }

  const iface = state.currentInterface;
  try {
    await runCmd(`wg-quick down ${iface}`);
    state.currentInterface = null;
    saveState(state);
    log.info("Desconectado:", iface);
    res.json({ status: "desconectado", interface: iface });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Status ────────────────────────────────────
app.get("/status", async (req, res) => {
  try {
    const { stdout } = await runCmd("wg show");
    const connected = stdout.includes("interface:");
    res.json({
      connected,
      current  : state.currentInterface,
      interfaces: parseWgShow(stdout),
    });
  } catch (e) {
    // wg show retorna erro se não houver interfaces activas
    res.json({ connected: false, current: null, interfaces: [] });
  }
});

app.post("/update-routing", (req, res) => {
  const { ip, gateway } = req.body;
  if (!ip || !gateway) {
    return res.status(400).json({ error: "Faltam IP ou Gateway" });
  }

  try {
    const files = fs.readdirSync(WG_DIR).filter(f => f.endsWith(".conf") && !f.startsWith("."));
    let atualizados = 0;

    for (const file of files) {
      const filePath = path.join(WG_DIR, file);
      let content = fs.readFileSync(filePath, "utf8");

      // 1. Extrair o domínio do servidor Surfshark (ex: ar-bua.prod.surfshark.com)
      const endpointMatch = content.match(/Endpoint\s*=\s*([^:]+):\d+/);
      const domain = endpointMatch ? endpointMatch[1] : "br-sao.prod.surfshark.com";

      // 2. Limpar regras antigas (se já existirem) para evitar duplicação
      content = content.replace(/^Post(?:Up|Down).*$/gm, "").replace(/\n{2,}/g, "\n");

      // 3. Criar as novas regras formatadas
// 3. Criar as novas regras formatadas (sem forçar o dev eth0)
// 3. Criar as novas regras com tolerância a falhas (|| true em todo o lado)
      const novasRegras = `
PostUp = ip rule add from ${ip} lookup main priority 100 || true
PostUp = ip route add $(getent ahostsv4 ${domain} | head -1 | awk '{print $1}') via ${gateway} || true
PostDown = ip rule del from ${ip} lookup main priority 100 || true
PostDown = ip route del $(getent ahostsv4 ${domain} | head -1 | awk '{print $1}') via ${gateway} || true
`;
      // 4. Inserir as novas regras exatamente antes da secção [Peer]
      if (content.includes("[Peer]")) {
        content = content.replace("[Peer]", novasRegras.trim() + "\n\n[Peer]");
      } else {
        content += "\n" + novasRegras.trim(); 
      }

      fs.writeFileSync(filePath, content.trim() + "\n", "utf8");
      atualizados++;
    }

    log.info(`Rotas injetadas em ${atualizados} ficheiros. IP: ${ip}, GW: ${gateway}`);
    res.json({ ok: true, message: `Rotas injetadas com sucesso em ${atualizados} ficheiros.` });
  } catch (e) {
    log.error("Erro ao atualizar rotas:", e.message);
    res.status(500).json({ error: "Falha ao atualizar rotas." });
  }
});


// ── Apagar config ─────────────────────────────
app.delete("/configs/:name", async (req, res) => {
  const iface = sanitizeIface(req.params.name);
  if (!iface) {
    return res.status(400).json({ error: "Nome inválido" });
  }

  // Não permite apagar a interface ativa
  if (state.currentInterface === iface) {
    return res.status(409).json({ error: "Desconecte antes de apagar a config ativa" });
  }

  const confPath = path.join(WG_DIR, `${iface}.conf`);
  if (!fs.existsSync(confPath)) {
    return res.status(404).json({ error: "Config não encontrada" });
  }

  try {
    fs.unlinkSync(confPath);
    log.info("Config apagada:", `${iface}.conf`);
    res.json({ ok: true, deleted: `${iface}.conf` });
  } catch (e) {
    log.error("Apagar config:", e.message);
    res.status(500).json({ error: "Falha ao apagar config" });
  }
});

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/**
 * Analisa a saída de `wg show` em objectos estruturados.
 */
function parseWgShow(output) {
  const interfaces = [];
  let current = null;

  for (const line of output.split("\n")) {
    const ifaceMatch = line.match(/^interface:\s+(.+)/);
    const peerMatch  = line.match(/^\s+peer:\s+(.+)/);
    const kvMatch    = line.match(/^\s+([a-z ]+):\s+(.+)/);

    if (ifaceMatch) {
      current = { name: ifaceMatch[1].trim(), peers: [] };
      interfaces.push(current);
    } else if (peerMatch && current) {
      current.peers.push({ pubkey: peerMatch[1].trim() });
    } else if (kvMatch && current) {
      const key = kvMatch[1].trim().replace(/ /g, "_");
      current[key] = kvMatch[2].trim();
    }
  }
  return interfaces;
}

// ─────────────────────────────────────────────
// Middleware de erros global
// ─────────────────────────────────────────────
app.use((err, req, res, _next) => {
  log.error("Unhandled:", err.message);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// ─────────────────────────────────────────────
// Graceful shutdown
// ─────────────────────────────────────────────
async function shutdown(signal) {
  log.info(`${signal} recebido. A encerrar...`);
  if (state.currentInterface) {
    try {
      await runCmd(`wg-quick down ${state.currentInterface}`);
      log.info("Interface desligada no shutdown:", state.currentInterface);
    } catch (e) {
      log.warn("Shutdown: falha ao desligar interface:", e.message);
    }
  }
  process.exit(0);
}
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// ─────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  log.info(`WireGuard Panel em http://localhost:${PORT}`);
  log.info(`Directório WG: ${WG_DIR}`);
  log.info(`Interface activa: ${state.currentInterface || "nenhuma"}`);
});
