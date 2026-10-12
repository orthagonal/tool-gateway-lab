import { runCases } from './src/architect-runner.js';
const results = runCases();
for (const r of results) console.log(`${r.passed ? 'PASS' : 'FAIL'}  ${r.id}  ${r.title.padEnd(36)} expected=${r.expected} actual=${r.actual}`);
const passed = results.filter(r => r.passed).length;
console.log(`\nGATEWAY SCORE: ${passed}/${results.length}`);
if (passed !== results.length) process.exitCode = 1;
