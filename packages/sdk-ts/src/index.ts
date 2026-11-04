/**
 * @nexuspanel/sdk-ts — reserved in P0.
 *
 * From P1 this client is GENERATED from the OpenAPI 3.1 artifact
 * (specs/nexuspanel-api-design-v2.0.md §7: openapi-typescript). Hand-written
 * request code here would drift from the contract; do not add any.
 */

export const SDK_VERSION = '0.1.0';
export const API_VERSION = 'v1';

export interface NexusPanelClientOptions {
  baseUrl: string; // e.g. https://panel.example.com/api/v1
  token: string; // JWT or scoped API token (API spec §2.2)
}

/** Placeholder until codegen lands in P1. */
export function createClient(_opts: NexusPanelClientOptions): never {
  throw new Error('SDK generation lands in P1 — see specs/nexuspanel-api-design-v2.0.md §7');
}
