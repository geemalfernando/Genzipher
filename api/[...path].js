import { getApp } from "../src/server.js";

function stripApiPrefix(req) {
  const url = typeof req.url === "string" ? req.url : "";
  if (url === "/api") req.url = "/";
  else if (url.startsWith("/api/")) req.url = url.slice(4) || "/";
}

export default async function handler(req, res) {
  stripApiPrefix(req);
  const app = await getApp();
  return app(req, res);
}

