import init, { SrpServer } from "srp-wasm/server";

export async function createSrpServer() {
  await init();

  return new SrpServer();
}
