import init, { SrpClient } from "../wasm_pkg/dist/client/index.js";

await init();

async function register() {
  const username = document.getElementById("reg-username").value.trim();
  const password = document.getElementById("reg-password").value;

  if (!username || !password) {
    log("Please enter username and password for registration.");
    return;
  }

  const client = new SrpClient();
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const verifier = client.verifier(salt, username, password);

  const body = {
    username,
    salt: Array.from(salt),
    verifier: Array.from(verifier),
  };

  const res = await fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (res.ok) {
    log(`Registered user "${username}"`);
  } else {
    log("Register failed: " + (await res.text()));
  }
}

async function login() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  if (!username || !password) {
    log("Please enter username and password for login.");
    return;
  }

  const client = new SrpClient();

  const a = client.generate_a();
  const A = client.compute_A(a);

  // Start auth, get salt and B from server
  let data = await fetch("/start-auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  });

  if (!data.ok) {
    log("Start auth failed: " + (await data.text()));
    return;
  }

  const { salt, B } = await data.json();

  // Compute M1 proof
  let verifier;
  try {
    verifier = client.srp_client_verifier(
      a,
      A,
      Uint8Array.from(B),
      Uint8Array.from(salt),
      username,
      password,
    );
  } catch (e) {
    log("Client verifier error: " + e.message);
    return;
  }

  // Send M1 proof to server for verification
  data = await fetch("/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      A: Array.from(A),
      clientM1: Array.from(verifier.client_proof()),
    }),
  });

  if (!data.ok) {
    log("Verification failed: " + (await data.text()));
    return;
  }

  const { serverM2 } = await data.json();

  // Verify server's proof M2
  if (verifier.verify_server(Uint8Array.from(serverM2))) {
    log("Login success!");
  } else {
    log("Server proof verification failed.");
  }
}

document.getElementById("btn-register").addEventListener("click", register);
document.getElementById("btn-login").addEventListener("click", login);

const logEl = document.getElementById("log");
function log(msg) {
  logEl.textContent += msg + "\n";
}
