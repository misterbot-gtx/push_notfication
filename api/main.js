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
dotenv.config({
  path: process.env.DOTENV_CONFIG_PATH
    ? process.env.DOTENV_CONFIG_PATH
    : fs.existsSync(envServerPath)
      ? envServerPath
      : envDefaultPath,
});

const app = express();
app.use(express.json());

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
  const v = (value || "").trim();
  if (!v) return null;
  if (v.toLowerCase().startsWith("bearer ")) return v.slice(7).trim();
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

function supabaseHeaders() {
  if (!supabase_url || !supabase_service_role_key) {
    throw new Error(
      "Supabase não configurado no servidor. Defina SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY."
    );
  }
  return {
    apikey: supabase_service_role_key,
    Authorization: `Bearer ${supabase_service_role_key}`,
    "Content-Type": "application/json",
  };
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
  return await getUserIdByRobotIdFromTokens(robotId);
}

async function getUserIdByRobotIdFromTokens(robotId) {
  const base = getSupabaseBaseUrl();
  const url = new URL(`${base}/rest/v1/user_push_tokens`);
  url.searchParams.set("select", "user_id");
  url.searchParams.set("robot_id", `eq.${robotId}`);
  url.searchParams.set("limit", "1");

  const r = await fetch(url.toString(), { headers: supabaseHeaders() });
  if (!r.ok) {
    throw new Error(
      `Erro ao buscar robot_id (tokens) no Supabase: ${await r.text()}`
    );
  }
  const rows = await r.json();
  return rows?.[0]?.user_id ?? null;
}

async function getFcmTokensByUserId(userId) {
  const base = getSupabaseBaseUrl();
  const url = new URL(`${base}/rest/v1/user_push_tokens`);
  url.searchParams.set("select", "fcm_token");
  url.searchParams.set("user_id", `eq.${userId}`);

  const r = await fetch(url.toString(), { headers: supabaseHeaders() });
  if (!r.ok) {
    throw new Error(`Erro ao buscar tokens no Supabase: ${await r.text()}`);
  }
  const rows = await r.json();
  return (rows || [])
    .map((x) => (x?.fcm_token || "").trim())
    .filter(Boolean);
}

async function getFcmTokensByRobotId(robotId) {
  const base = getSupabaseBaseUrl();
  const url = new URL(`${base}/rest/v1/user_push_tokens`);
  url.searchParams.set("select", "fcm_token");
  url.searchParams.set("robot_id", `eq.${robotId}`);

  const r = await fetch(url.toString(), { headers: supabaseHeaders() });
  if (!r.ok) {
    throw new Error(
      `Erro ao buscar tokens por robot_id no Supabase: ${await r.text()}`
    );
  }
  const rows = await r.json();
  return (rows || [])
    .map((x) => (x?.fcm_token || "").trim())
    .filter(Boolean);
}

async function deleteFcmToken(token) {
  const base = getSupabaseBaseUrl();
  const url = new URL(`${base}/rest/v1/user_push_tokens`);
  url.searchParams.set("fcm_token", `eq.${token}`);

  await fetch(url.toString(), {
    method: "DELETE",
    headers: supabaseHeaders(),
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

    const { titulo, body, som, canal, imageUrl } = req.body;
    if (!titulo || !body || !som || !canal) {
      return res.status(400).json({
        error:
          'Os campos "titulo", "body", "som" e "canal" são obrigatórios e "imageUrl" caso queira colocar uma imagem.',
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
      const tokensByRobotId = await getFcmTokensByRobotId(auth);
      if (tokensByRobotId.length) {
        targetTokens.push(...tokensByRobotId);
      } else {
        const userId = await getUserIdByRobotId(auth);
        if (!userId) {
          return res.status(404).json({
            error:
              "Robot ID não encontrado. Verifique se o app já salvou o robot_id e registrou o token no Supabase.",
          });
        }
        const tokens = await getFcmTokensByUserId(userId);
        if (!tokens.length) {
          return res
            .status(404)
            .json({ error: "Nenhum token registrado para este usuário." });
        }
        targetTokens.push(...tokens);
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
          try {
            await deleteFcmToken(token);
          } catch (_) {}
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});
