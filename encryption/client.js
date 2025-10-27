const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
const users = new Map();

// === Generate RSA key pair untuk tiap client ===
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// export publicKey PEM for sending
const myPublicKeyPem = publicKey.export({ type: "pkcs1", format: "pem" });
// keep privateKey as KeyObject (we will export when decrypting)

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);

    // Kirim public key ke server (PEM string)
    socket.emit("registerPublicKey", {
      username,
      publicKey: myPublicKeyPem,
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        if ((match = message.match(/^!secret (\w+)$/))) {
          targetUsername = match[1];
          console.log(`Now secretly chatting with ${targetUsername}`);
        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
        } else {
          // === Jika sedang dalam mode secret ===
          if (targetUsername && users.has(targetUsername)) {
            const targetPublicKeyPem = users.get(targetUsername);

            // gunakan padding OAEP untuk enkripsi (dan nanti dekripsi juga OAEP)
            const encryptedMessageBuf = crypto.publicEncrypt(
              {
                key: targetPublicKeyPem,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
              },
              Buffer.from(message, "utf8")
            );

            socket.emit("message", {
              username,
              message: encryptedMessageBuf.toString("base64"), // kirim ciphertext
            });
          } else {
            // Kirim pesan biasa
            socket.emit("message", { username, message });
          }
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} join the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage } = data;

  if (senderUsername !== username) {
    let outputMessage = senderMessage;

    // coba decrypt menggunakan privateKey dengan padding OAEP (harus sama dengan encrypt)
    try {
      const decrypted = crypto.privateDecrypt(
        {
          key: privateKey.export({ type: "pkcs1", format: "pem" }),
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        Buffer.from(senderMessage, "base64")
      );
      outputMessage = decrypted.toString("utf8");
    } catch (err) {
      // gagal decrypt -> bukan untuk kita atau bukan ciphertext OAEP; tampilkan ciphertext
    }

    console.log(`${senderUsername}: ${outputMessage}`);
    rl.prompt();
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
