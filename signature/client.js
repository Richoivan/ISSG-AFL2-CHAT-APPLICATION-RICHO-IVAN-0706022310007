const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: ">",
});

let registeredUsername = "";
let username = "";
const users = new Map(); // map username -> publicKey PEM (string)

// generate initial RSA keypair for this client
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

// current keypair used to sign messages (will be replaced on impersonate)
let myKeyPair = generateKeyPair();
let myPrivateKeyPem = myKeyPair.privateKey;
let myPublicKeyPem = myKeyPair.publicKey;

// helper: sign message (returns base64 signature)
function signMessage(message, privateKeyPem) {
  const sign = crypto.createSign("sha256");
  sign.update(message, "utf8");
  sign.end();
  const signature = sign.sign(privateKeyPem);
  return signature.toString("base64");
}

// helper: verify signature (signature base64) using sender publicKey PEM
function verifySignature(message, signatureBase64, publicKeyPem) {
  try {
    const verify = crypto.createVerify("sha256");
    verify.update(message, "utf8");
    verify.end();
    const signatureBuf = Buffer.from(signatureBase64, "base64");
    return verify.verify(publicKeyPem, signatureBuf);
  } catch (e) {
    return false;
  }
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    // register our initial public key with server
    socket.emit("registerPublicKey", {
      username,
      publicKey: myPublicKeyPem,
    });

    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        // command: impersonate
        let match;
        if ((match = message.match(/^!impersonate (\w+)$/))) {
          const target = match[1];

          // generate new keypair for impersonation and replace current keys
          myKeyPair = generateKeyPair();
          myPrivateKeyPem = myKeyPair.privateKey;
          myPublicKeyPem = myKeyPair.publicKey;

          // change displayed username (we are now sending as target)
          username = target;
          console.log(`Now impersonating as ${username}`);

          // notify server that this username has a (new) public key
          socket.emit("registerPublicKey", {
            username,
            publicKey: myPublicKeyPem,
          });
        } else if (message.match(/^!exit$/)) {
          username = registeredUsername;
          console.log(`Now you are ${username}`);

          // restore original keypair for the registered username
          // (optional: regenerate original keypair or reuse prior; here we regenerate)
          myKeyPair = generateKeyPair();
          myPrivateKeyPem = myKeyPair.privateKey;
          myPublicKeyPem = myKeyPair.publicKey;

          socket.emit("registerPublicKey", {
            username,
            publicKey: myPublicKeyPem,
          });
        } else {
          // normal message: sign with current private key and send signature
          const signature = signMessage(message, myPrivateKeyPem);
          socket.emit("message", { username, message, signature });
        }
      }
      rl.prompt();
    });
  });
});

// server sends initial keys as array of [user, key]
socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUser, publicKey } = data;

  // if we already know this user's key, but it changed -> suspicious
  if (users.has(newUser)) {
    const oldKey = users.get(newUser);
    if (oldKey !== publicKey) {
      console.log("[WARNING] this user is fake (public key changed)");
    }
  }

  users.set(newUser, publicKey);
  console.log(`${newUser} join the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  // expecting { username, message, signature? }
  const { username: senderUsername, message: senderMessage, signature } = data;

  if (senderUsername !== username) {
    const senderPublicKey = users.get(senderUsername);

    if (!senderPublicKey) {
      // we don't have a public key for this sender -> suspicious
      console.log("[WARNING] this user is fake (no public key known)");
      console.log(`${senderUsername}: ${senderMessage}`);
    } else {
      // if no signature provided -> suspicious
      if (!signature) {
        console.log("[WARNING] this user is fake (no signature)");
        console.log(`${senderUsername}: ${senderMessage}`);
      } else {
        const ok = verifySignature(senderMessage, signature, senderPublicKey);
        if (!ok) {
          console.log("[WARNING] this user is fake (signature invalid)");
          console.log(`${senderUsername}: ${senderMessage}`);
        } else {
          // valid
          console.log(`${senderUsername}: ${senderMessage}`);
        }
      }
    }
  }
  rl.prompt();
});

socket.on("disconnect", () => {
  console.log("Disconnected from server");
  rl.close();
  process.exit(0);
});
rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
