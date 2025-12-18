import { createClient } from "redis";
import { redis as _redis } from "./";


const client = createClient({
  socket: {
    host: _redis.host,
    port: _redis.port,
  },
  password: _redis.password || undefined,
});

client.on('error', (err) => console.log("Redis error", err))
(async () => await client.connect())()

export default client