# FCM Push Server - Backend para Notificações Push

Este projeto é um backend em Node.js para envio de notificações **push** utilizando o **Firebase Cloud Messaging (FCM)** via API HTTP v1.  
A autenticação é feita com **JWT** usando credenciais definidas no arquivo `.env`.

<p align="center">
  <img src="./preview.png" alt="Pushcut Preview" width="800"/>
</p>

🎥 **Vídeo de demonstração:**
[Assista no TikTok](https://www.tiktok.com/@mr.robots777/video/7537375102602644742)

## 📌 Funcionalidade

- Gera automaticamente o token de acesso para a API do FCM usando as credenciais do serviço.
- Cacheia o token em `token.json` para evitar múltiplas requisições de autenticação.
- Recebe requisições POST contendo os dados da notificação (título, corpo, som, canal, imagem opcional).
- Envia notificações para dispositivos Android e iOS.
- Configurações sensíveis via `.env`.

---

## 📂 Estrutura de Arquivos



fcm-push-server/
│── server.js          # Código principal do backend
│── package.json       # Configuração do projeto Node.js
│── token.json         # Cache do token gerado (criado automaticamente)
│── .env               # Credenciais e variáveis de ambiente
│── .env.example       # Modelo de configuração para o .env
│── README.txt         # Este arquivo



---

## ⚙️ Variáveis de Ambiente (`.env`)

 ```
PRIVATE\_KEY="-----BEGIN PRIVATE KEY-----\nSEU\_CONTEUDO\_AQUI\n-----END PRIVATE KEY-----\n"
PROJECT\_ID="seu-project-id"
CLIENT\_EMAIL="firebase-adminsdk@seu-project-id.iam.gserviceaccount.com"
PORT=3000
 ```
<br>

> **IMPORTANTE:** A `PRIVATE_KEY` deve conter `\n` no lugar das quebras de linha.

---

## 🚀 Como Rodar

1. Instalar dependências:
   ```bash
   npm install
    ```

2. Configurar o `.env` conforme o modelo.

3. Rodar o servidor:

   ```bash
   npm run dev   # Modo desenvolvimento
   npm start     # Produção
   ```

---

## 📡 Endpoint

**POST /**
Envia uma notificação push para o token informado no header `Authorization`.

### Corpo da requisição:

```json
{
  "titulo": "Título da notificação",
  "body": "Mensagem da notificação",
  "som": "default",
  "canal": "meu_canal",
  "imageUrl": "https://exemplo.com/imagem.png"
}
```

### Headers:

```
Authorization: TOKEN_DO_DISPOSITIVO
Content-Type: application/json
```

### Resposta de sucesso:

```json
{
  "success": "200",
  "response": "Notificação enviada com sucesso."
}
```

---

## 📄 Licença

MIT - Uso livre para fins pessoais e comerciais.
