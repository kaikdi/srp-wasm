import { test, expect } from "@playwright/test";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let serverProcess;

test.beforeAll(async () => {
  serverProcess = spawn(
    "node",
    [path.resolve(__dirname, "../dist/server.js")],
    {
      stdio: "inherit",
    },
  );
  await new Promise((resolve) => setTimeout(resolve, 1000)); // wait for server
});

test.afterAll(() => {
  serverProcess?.kill();
});

test("SRP register and login flow works", async ({ page }) => {
  await page.goto("http://localhost:3000");

  // Fill register form
  await page.fill("#reg-username", "user1");
  await page.fill("#reg-password", "pass123");
  await page.click("#btn-register");

  // Fill login form
  await page.fill("#login-username", "user1");
  await page.fill("#login-password", "pass123");
  await page.click("#btn-login");

  // Wait for result
  await page.waitForTimeout(500);

  const log = await page.textContent("#log");
  expect(log).toContain("Login success!");
});
