const redis = require("redis");
const vars = require("./");


const client = redis.createClient({
  socket: {
    host: vars.redis.host,
    port: vars.redis.port,
  },
  password: vars.redis.password || undefined,
});

client.on('error', (err) => console.log("Redis error", err))
(async () => await client.connect())()

module.exports = client