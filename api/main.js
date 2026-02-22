import express from "express";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envServerPath = path.join(__dirname, ".env.server");
const envDefaultPath = path.join(__dirname, ".env");
const envRootPath = path.resolve(__dirname, "..", ".env");
dotenv.config({
  path: process.env.DOTENV_CONFIG_PATH
    ? process.env.DOTENV_CONFIG_PATH
    : fs.existsSync(envServerPath)
      ? envServerPath
      : fs.existsSync(envDefaultPath)
        ? envDefaultPath
        : fs.existsSync(envRootPath)
          ? envRootPath
          : undefined,
});

const app = express();
app.use(express.json());
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({
      error: "JSON inválido no corpo da requisição.",
      hint: 'Envie um único objeto JSON válido e defina "Content-Type: application/json".',
    });
  }
  return next(err);
});

const private_key = (process.env.PRIVATE_KEY || "").replace(/\\n/g, "\n");
const project_id = process.env.PROJECT_ID;
const client_email = process.env.CLIENT_EMAIL;
const token_uri = "https://oauth2.googleapis.com/token";
const scope = "https://www.googleapis.com/auth/cloud-platform";

const supabase_url = process.env.SUPABASE_URL;
const supabase_service_role_key = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Cache simples em memória para token
let cachedToken = null;
let tokenExpiresAt = 0;

function parseAuthorizationHeader(value) {
  const v = (value || "").trim().replace(/[`'"]/g, "");
  if (!v) return null;
  if (v.toLowerCase().startsWith("bearer ")) {
    return v.slice(7).trim().replace(/[`'"]/g, "");
  }
  return v;
}

function isRobotId(value) {
  return typeof value === "string" && value.startsWith("robot-");
}

function sanitizeImageUrl(value) {
  const v = (value || "").trim();
  if (!v) return null;
  return v.replace(/`/g, "").trim();
}

function resolveChannelIdBySound(sound) {
  const s = (sound || "").toString().trim();
  if (!s) return null;
  if (s === "venda") return "heisencut_venda";
  if (s === "contact") return "heisencut_contact";
  if (s === "newclient") return "heisencut_newclient";
  return null;
}

function getSupabaseKeyType() {
  const k = (supabase_service_role_key || "").trim();
  if (!k) return null;
  if (k.startsWith("sb_publishable_")) return "publishable";
  if (k.startsWith("sb_secret_")) return "secret";
  if (k.split(".").length >= 3) return "jwt";
  return "unknown";
}

function assertSupabaseServerKey() {
  const k = (supabase_service_role_key || "").trim();
  const type = getSupabaseKeyType();
  if (!k) {
    throw new Error(
      "Supabase não configurado no servidor. Defina SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY."
    );
  }
  if (type === "publishable") {
    throw new Error(
      "SUPABASE_SERVICE_ROLE_KEY inválida (publishable). Use a chave secret/service_role do projeto Supabase."
    );
  }
  if (type === "secret") return;
  if (type === "jwt") {
    const role = getSupabaseKeyRole();
    if (!role) {
      throw new Error(
        "SUPABASE_SERVICE_ROLE_KEY inválida. Use a chave secret/service_role do projeto Supabase."
      );
    }
    if (role !== "service_role") {
      throw new Error(
        `SUPABASE_SERVICE_ROLE_KEY inválida (role=${role}). Use a chave service_role do projeto Supabase.`
      );
    }
    return;
  }
  throw new Error(
    "SUPABASE_SERVICE_ROLE_KEY inválida. Use a chave secret/service_role do projeto Supabase."
  );
}

function supabaseHeaders() {
  if (!supabase_url || !supabase_service_role_key) {
    throw new Error(
      "Supabase não configurado no servidor. Defina SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY."
    );
  }
  assertSupabaseServerKey();
  return {
    apikey: supabase_service_role_key,
    Authorization: `Bearer ${supabase_service_role_key}`,
    "Content-Type": "application/json",
  };
}

function decodeJwtPayload(token) {
  const t = (token || "").trim();
  const parts = t.split(".");
  if (parts.length < 2) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(b64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch (_) {
    return null;
  }
}

function getSupabaseKeyRole() {
  const payload = decodeJwtPayload(supabase_service_role_key);
  return payload?.role || null;
}

function getSupabaseKeyRef() {
  const payload = decodeJwtPayload(supabase_service_role_key);
  return payload?.ref || null;
}

function getSupabaseKeyIss() {
  const payload = decodeJwtPayload(supabase_service_role_key);
  return payload?.iss || null;
}

function getSupabaseBaseUrl() {
  if (!supabase_url) {
    throw new Error(
      "Supabase não configurado no servidor. Defina SUPABASE_URL."
    );
  }
  try {
    const u = new URL(supabase_url);
    return u.toString().replace(/\/+$/, "");
  } catch (_) {
    throw new Error(
      "SUPABASE_URL inválida. Use o formato https://SEU-PROJETO.supabase.co"
    );
  }
}

function getSupabaseHost() {
  try {
    return new URL(getSupabaseBaseUrl()).host;
  } catch (_) {
    return null;
  }
}

app.get("/health", (req, res) => {
  return res.json({
    ok: true,
    project_id: project_id || null,
    supabase_host: getSupabaseHost(),
    has_supabase_service_role_key: Boolean(supabase_service_role_key),
    supabase_key_type: getSupabaseKeyType(),
    supabase_key_role: getSupabaseKeyRole(),
    supabase_key_ref: getSupabaseKeyRef(),
    supabase_key_iss: getSupabaseKeyIss(),
  });
});

async function getUserIdByRobotId(robotId) {
  const base = getSupabaseBaseUrl();
  const url = new URL(`${base}/rest/v1/user_profiles`);
  url.searchParams.set("select", "id");
  url.searchParams.set("robot_id", `eq.${robotId}`);
  url.searchParams.set("limit", "1");

  const r = await fetch(url.toString(), { headers: supabaseHeaders() });
  if (!r.ok) {
    throw new Error(`Erro ao buscar robot_id no Supabase: ${await r.text()}`);
  }
  const rows = await r.json();
  const fromProfiles = rows?.[0]?.id ?? null;
  if (fromProfiles) return fromProfiles;
  return null;
}

async function getProfileTokenByRobotId(robotId) {
  const base = getSupabaseBaseUrl();
  const url = new URL(`${base}/rest/v1/user_profiles`);
  url.searchParams.set("select", "fcm_token");
  url.searchParams.set("robot_id", `eq.${robotId}`);
  url.searchParams.set("limit", "1");

  const r = await fetch(url.toString(), { headers: supabaseHeaders() });
  if (!r.ok) {
    throw new Error(
      `Erro ao buscar token (profile) no Supabase: ${await r.text()}`
    );
  }
  const rows = await r.json();
  const token = (rows?.[0]?.fcm_token || "").trim();
  return token || null;
}

async function clearProfileTokenByRobotId(robotId) {
  const base = getSupabaseBaseUrl();
  const url = new URL(`${base}/rest/v1/user_profiles`);
  url.searchParams.set("robot_id", `eq.${robotId}`);

  await fetch(url.toString(), {
    method: "PATCH",
    headers: supabaseHeaders(),
    body: JSON.stringify({
      fcm_token: null,
      fcm_last_seen_at: null,
    }),
  });
}

function isUnregisteredFcmError(bodyText) {
  const t = (bodyText || "").toString();
  return (
    t.includes('"errorCode": "UNREGISTERED"') ||
    t.includes("NotRegistered") ||
    t.includes("UNREGISTERED")
  );
}

// Gerar token de acesso
async function generateAccessToken() {
  if (!private_key || !client_email || !project_id) {
    throw new Error(
      "Credenciais do Firebase ausentes. Defina PRIVATE_KEY, CLIENT_EMAIL e PROJECT_ID."
    );
  }
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;

  const payload = {
    iss: client_email,
    scope,
    aud: token_uri,
    iat,
    exp,
  };

  const signedJwt = jwt.sign(payload, private_key, { algorithm: "RS256" });

  const res = await fetch(token_uri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: signedJwt,
    }),
  });

  if (!res.ok) {
    throw new Error(`Erro ao obter token: ${await res.text()}`);
  }

  const data = await res.json();
  return {
    access_token: data.access_token,
    expires_at: Date.now() + (data.expires_in || 3600) * 1000,
  };
}

// Obter token válido (do cache ou novo)
async function getAccessToken() {
  if (cachedToken && tokenExpiresAt > Date.now()) {
    return cachedToken;
  }
  const tokenData = await generateAccessToken();
  cachedToken = tokenData.access_token;
  tokenExpiresAt = tokenData.expires_at;
  return cachedToken;
}

// Rota principal
app.post("/", async (req, res) => {
  try {
    const serverKey = await getAccessToken();

    const { titulo, body, som, imageUrl } = req.body;
    if (!titulo || !body || !som) {
      return res.status(400).json({
        error:
          'Os campos "titulo", "body" e "som" são obrigatórios e "imageUrl" caso queira colocar uma imagem.',
      });
    }

    const canal = resolveChannelIdBySound(som);
    if (!canal) {
      return res.status(400).json({
        error:
          'Som inválido. Use "newclient", "contact" ou "venda" para definir o canal automaticamente.',
      });
    }

    const auth = parseAuthorizationHeader(req.headers["authorization"]);
    if (!auth) {
      return res.status(401).json({ error: "Token de autorização ausente." });
    }

    const image = sanitizeImageUrl(imageUrl);

    const baseMessage = {
      message: {
        notification: {
          title: titulo,
          body,
          image: image || undefined,
        },
        android: {
          notification: {
            sound: som,
            channel_id: canal,
            image: image || undefined,
            icon: "ic_shortcut_icone",
          },
        },
        apns: {
          payload: {
            aps: {
              sound: `${som}.caf`,
              "mutable-content": 1,
            },
          },
          fcm_options: {
            image: image || undefined,
          },
        },
        data: {
          title: titulo,
          body,
          som,
          canal,
          ...(image ? { image } : {}),
        },
      },
    };

    const targetTokens = [];

    if (isRobotId(auth)) {
      const profileToken = await getProfileTokenByRobotId(auth);
      if (profileToken) {
        targetTokens.push(profileToken);
      }

      if (!targetTokens.length) {
        const userId = await getUserIdByRobotId(auth);
        return res.status(404).json({
          error:
            userId == null
              ? "Robot ID não encontrado (ou sem permissão/RLS). Verifique o robot_id no user_profiles e a chave SUPABASE_SERVICE_ROLE_KEY."
              : "Nenhum token registrado para este usuário.",
          debug: {
            supabase_host: getSupabaseHost(),
            robot_id: auth,
          },
        });
      }
    } else {
      targetTokens.push(auth);
    }

    const sendUrl = `https://fcm.googleapis.com/v1/projects/${project_id}/messages:send`;
    const headers = {
      Authorization: `Bearer ${serverKey}`,
      "Content-Type": "application/json",
    };

    const results = await Promise.all(
      targetTokens.map(async (token) => {
        const payload = {
          ...baseMessage,
          message: {
            ...baseMessage.message,
            token,
          },
        };

        const r = await fetch(sendUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
        });

        const text = await r.text();
        if (!r.ok && isUnregisteredFcmError(text)) {
          if (isRobotId(auth)) {
            try {
              await clearProfileTokenByRobotId(auth);
            } catch (_) {}
          }
        }

        return {
          ok: r.ok,
          status: r.status,
          response: text,
        };
      })
    );

    const okCount = results.filter((x) => x.ok).length;
    const failCount = results.length - okCount;

    if (failCount === 0) {
      return res.json({
        success: "200",
        sent: okCount,
        response: "Notificação enviada com sucesso.",
      });
    }

    return res.status(207).json({
      error: "Falha parcial ao enviar notificação.",
      sent: okCount,
      failed: failCount,
      results: results.map((r, i) => ({
        index: i,
        ok: r.ok,
        http_code: r.status,
        response: r.response,
      })),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get("/", (req, res) => {
  return res.json({
    servidor: "ativo",
  });
});

const PORT = process.env.PORT || 3000;
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
  });
}

export default app;
