const WebSocket = require("ws");

const ws = new WebSocket("ws://127.0.0.1:4000/ws");

ws.on("open", () => console.log("OPEN"));
ws.on("message", msg => console.log("MSG:", msg.toString()));
ws.on("error", err => {
  console.error("ERROR:", err);
});
ws.on("close", (code, reason) =>
  console.log("CLOSED", code, reason.toString())
);
