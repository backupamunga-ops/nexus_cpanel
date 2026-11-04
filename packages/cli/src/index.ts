#!/usr/bin/env node
/**
 * nexus — NexusPanel CLI (reserved in P0, implemented in P2).
 * Every command maps to a documented API endpoint and vice versa; CI enforces
 * the 1:1 mapping against the OpenAPI catalog (specs/nexuspanel-api-design-v2.0.md §7).
 */
const args = process.argv.slice(2);
console.log(`nexus v0.1.0 — CLI implementation lands in P2 (got: ${args.join(' ') || 'no args'})`);
console.log('See specs/nexuspanel-api-design-v2.0.md for the endpoint catalog it will cover.');
process.exit(0);
