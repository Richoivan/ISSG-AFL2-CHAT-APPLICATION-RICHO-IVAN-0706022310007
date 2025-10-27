const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer();
const io = socketIo(server);

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);

  socket.on("message", (data) => {
    const { username, message } = data;
    io.emit("message", { username, message });
  });
  
   socket.on("disconnect", () => {
  console.log(`Client ${socket.id} disconnected`);
  });
});


const port = 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});