import init, { SrpClient } from "srp-wasm/client";

export async function createSrpClient() {
  await init();

  return new SrpClient();
}
