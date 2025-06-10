import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { SrpServer } from "../wasm_pkg/dist/server/index.js";
import session from "express-session";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(__dirname));
app.use("/wasm_pkg", express.static(path.join(__dirname, "../wasm_pkg")));
app.use(
  session({
    secret: "srp",
    resave: false,
    saveUninitialized: false,
  }),
);

const srpServer = new SrpServer();

let users = {};

app.post("/register", (req, res) => {
  const { username, salt, verifier } = req.body;
  users[username] = {
    salt: Uint8Array.from(salt),
    verifier: Uint8Array.from(verifier),
  };
  res.json({
    ok: true,
  });
});

app.post("/start-auth", (req, res) => {
  const { username } = req.body;
  const user = users[username];

  if (!user) {
    return res.status(400).json({
      error: "User not found",
    });
  }

  try {
    const b = srpServer.generate_b();
    const B = srpServer.compute_B(user.verifier, b);

    // Sessions serialize data as JSON, which doesn’t support Uint8Array. Convert to Array to preserve data correctly.
    req.session.b = Array.from(b);
    req.session.B = Array.from(B);

    res.json({
      salt: Array.from(user.salt),
      B: Array.from(B),
    });
  } catch (e) {
    res.status(500).json({
      error: e.message,
    });
  }
});

app.post("/verify", (req, res) => {
  const { username, A, clientM1 } = req.body;
  const user = users[username];

  if (!user) {
    return res.status(400).json({
      error: "User not found",
    });
  }

  try {
    const { b, B } = req.session;

    const verifier = srpServer.srp_server_verifier(
      Uint8Array.from(A),
      Uint8Array.from(b),
      Uint8Array.from(B),
      user.verifier,
      user.salt,
      username,
    );

    const verified = verifier.verify_client(Uint8Array.from(clientM1));

    if (!verified) {
      return res.status(400).json({
        error: "Verification failed",
      });
    }

    const serverM2 = verifier.server_proof();
    res.json({
      serverM2: Array.from(serverM2),
    });
  } catch (e) {
    console.log(e);

    res.status(500).json({
      error: e.message,
    });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
