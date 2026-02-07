import mongoose from "mongoose";

export async function connectMongo() {
  const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/genzipher_mvp";
  mongoose.set("strictQuery", true);
  const ready = mongoose.connection?.readyState;
  if (ready === 1) return mongoose.connection;
  if (!globalThis.__gz_mongoPromise) {
    globalThis.__gz_mongoPromise = mongoose.connect(uri, {
      autoIndex: true,
    });
  }
  await globalThis.__gz_mongoPromise;
  return mongoose.connection;
}
