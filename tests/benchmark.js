import redis from '../src/config/redis.js';
import { cacheRoles, getCachedRoles } from '../src/utils/redis.js';
import { performance } from 'perf_hooks';

const RUNS = 10000; // Number of operations
const userId = "bench-user-1";
const roles = ["admin", "editor", "viewer", "manager"];

async function runBenchmark() {
  console.log(`🚀 Starting Benchmark: ${RUNS} operations...`);

  // --- Test 1: Writing (SET) ---
  const startWrite = performance.now();
  for (let i = 0; i < RUNS; i++) {
    await cacheRoles(`${userId}-${i}`, roles);
  }
  const endWrite = performance.now();
  const writeTime = (endWrite - startWrite) / 1000;

  // --- Test 2: Reading (GET) ---
  const startRead = performance.now();
  for (let i = 0; i < RUNS; i++) {
    await getCachedRoles(`${userId}-${i}`);
  }
  const endRead = performance.now();
  const readTime = (endRead - startRead) / 1000;

  console.log('-------------------------------');
  console.log(`Results for ${RUNS} operations:`);
  console.log(`Write (SET): ${writeTime.toFixed(4)}s (${Math.round(RUNS / writeTime)} ops/s)`);
  console.log(`Read  (GET): ${readTime.toFixed(4)}s (${Math.round(RUNS / readTime)} ops/s)`);
  console.log('-------------------------------');

  await redis.quit();
}

runBenchmark().catch(console.error);