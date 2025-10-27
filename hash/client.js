const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: ">",
});

let username = "";


function sha256hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

socket.on("connect", () => {
  console.log("Connected to the server");
  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
       
        const hash = sha256hex(message);
        socket.emit("message", { username, message, hash });
      }
      rl.prompt();
    });
  });
});

socket.on("message", (data) => {
  
  const { username: senderUsername, message: senderMessage, hash: senderHash } = data;

  // 
  if (senderUsername !== username) {
    // jika server tidak mengirim hash sama sekali -> curiga
    if (!senderHash) {
      console.log("[WARNING] The message may have been changed during transmission (no hash present).");
      console.log(`${senderUsername}: ${senderMessage}`);
    } else {
      // membandingkan hash yang dikirim dengan hash computed dari message yang diterima
      const computed = sha256hex(senderMessage);
      if (computed !== senderHash) {
        console.log("[WARNING] The message may have been changed during transmission (hash mismatch).");
        console.log(`${senderUsername}: ${senderMessage}`);
      } else {
        // valid
        console.log(`${senderUsername}: ${senderMessage}`);
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
