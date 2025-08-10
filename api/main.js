import express from "express";
import fs from "fs";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const __dirname = path.resolve();
const tokenFilePath = path.join(__dirname, "token.json");

const private_key = process.env.PRIVATE_KEY.replace(/\\n/g, "\n");
const project_id = process.env.PROJECT_ID;
const client_email = process.env.CLIENT_EMAIL;
const token_uri = "https://oauth2.googleapis.com/token";
const scope = "https://www.googleapis.com/auth/cloud-platform";

// Gerar token de acesso
async function generateAccessToken() {
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

// Carregar token salvo se válido
function loadToken(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const tokenData = JSON.parse(fs.readFileSync(filePath, "utf8"));
  if (!tokenData.access_token || !tokenData.expires_at) return null;
  if (tokenData.expires_at > Date.now()) return tokenData.access_token;
  return null;
}

// Salvar token
function saveToken(filePath, accessToken, expiresAt) {
  fs.writeFileSync(
    filePath,
    JSON.stringify({ access_token: accessToken, expires_at: expiresAt })
  );
}

// Rota principal
app.post("/", async (req, res) => {
  try {
    let serverKey = loadToken(tokenFilePath);
    if (!serverKey) {
      const tokenData = await generateAccessToken();
      serverKey = tokenData.access_token;
      saveToken(tokenFilePath, serverKey, tokenData.expires_at);
    }

    const { titulo, body, som, canal, imageUrl } = req.body;
    if (!titulo || !body || !som || !canal) {
      return res.status(400).json({
        error:
          'Os campos "titulo", "body", "som" e "canal" são obrigatórios e "imageUrl" caso queira colocar uma imagem.',
      });
    }

    const deviceToken = req.headers["authorization"];
    if (!deviceToken) {
      return res.status(401).json({ error: "Token de autorização ausente." });
    }

    const notificationPayload = {
      message: {
        token: deviceToken.trim(),
        notification: {
          title: titulo,
          body: body,
          image: imageUrl || undefined,
        },
        android: {
          notification: {
            sound: som,
            channel_id: canal,
            image: imageUrl || undefined,
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
            image: imageUrl || undefined,
          },
        },
        data: {
          key1: "valor1",
          key2: "valor2",
        },
      },
    };

    const fcmRes = await fetch(
      `https://fcm.googleapis.com/v1/projects/${project_id}/messages:send`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${serverKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(notificationPayload),
      }
    );

    if (fcmRes.ok) {
      return res.json({
        success: "200",
        response: "Notificação enviada com sucesso.",
      });
    } else {
      const errorText = await fcmRes.text();
      return res.status(500).json({
        error: "Falha ao enviar notificação.",
        http_code: fcmRes.status,
        response: errorText || "Token Fornecido incorreto",
      });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});
