# srp-wasm

A WebAssembly-powered SRP (Secure Remote Password) implementation for secure, zero-knowledge authentication. This library provides both client-side and server-side SRP logic for use in web apps and Node.js environments.

---

## ✨ Features

- SRP-6a protocol (safe, zero-knowledge password authentication)
- WebAssembly speed and safety
- Browser and Node.js support
- Simple API
- Compatible with Express, fetch, etc.

---

## 📦 Installation

```bash
npm install srp-wasm
```

### Client initialization (Browser)

```js
import init, { SrpClient } from "srp-wasm/client";
// required for browser usage
await init();

const srpClient = new SrpClient();
```

### Server initialization (Node.js)

```js
import { SrpServer } from "srp-wasm/server";

const srpServer = new SrpServer();
```

SRP Authentication Flow

1. Registration (once):

- Client:

  - Generates salt and verifier from username + password

    ```js
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const verifier = client.verifier(salt, username, password);
    ```

  - Sends { username, salt, verifier } to server

- Server:

  - Stores { username, salt, verifier }

2. Login:

- Client:

  - Generates a, computes A

    ```js
    const a = client.generate_a();
    const A = client.compute_A(a);
    ```

  - Sends { username } to server

- Server:

  - Looks up user
  - Generates b, computes B

    ```js
    const b = srpServer.generate_b();
    const B = srpServer.compute_B(user.verifier, b);
    ```

  - Sends { salt, B } back

- Client:

  - Computes client proof (M1)

    ```js
    const verifier = client.srp_client_verifier(
      a,
      A,
      Uint8Array.from(B),
      Uint8Array.from(salt),
      username,
      password,
    );

    const m1 = verifier.client_proof();
    ```

  - Sends { A, M1 } to server

- Server:

  - Verifies client proof (M1)

    ```js
    const verifier = srpServer.srp_server_verifier(
      Uint8Array.from(A),
      Uint8Array.from(b),
      Uint8Array.from(B),
      user.verifier,
      user.salt,
      username,
    );

    const verified = verifier.verify_client(Uint8Array.from(clientM1));
    ```

  - If valid, sends back server proof (M2)

    ```js
    const m2 = verifier.server_proof();
    ```

- Client:

  - Verifies M2

    ```js
    verifier.verify_server(Uint8Array.from(serverM2));
    ```
