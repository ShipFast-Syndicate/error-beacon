// Shared hostile fixtures: every value below is something the ADR forbids in a
// captured event. PII_NEEDLES are the exact strings that must never be found
// anywhere in what is pushed to Loki (labels or log line).

// Assembled at runtime so no secret-shaped literal sits in the repository (gitleaks).
const JWT = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiI0ODIxMyJ9', 'c2lnbmF0dXJl'].join('.');
const STRIPE_KEY = ['sk', 'live', '51HxExampleKey'].join('_');

export const PII_NEEDLES = [
  'jean.dupont@example.com',
  'dupont',
  '203.0.113.42',
  '2001:db8:85a3::8a2e:370:7334',
  '48213',
  'user_8f3a91c2',
  'hunter2',
  STRIPE_KEY,
  'sessionabc123',
  'card=4111111111111111',
  '4111111111111111',
  JWT,
  '550e8400-e29b-41d4-a716-446655440000',
  '/home/jdupont/',
  'reset-token-9d8c7b',
  'Marie Curie',
];

export const HOSTILE_MESSAGE =
  'Failed for jean.dupont@example.com (user_8f3a91c2, id 48213) from 203.0.113.42 / 2001:db8:85a3::8a2e:370:7334 ' +
  'GET https://app.example.com/orders/48213?email=jean.dupont@example.com&token=reset-token-9d8c7b#frag ' +
  `password=hunter2 api_key: ${STRIPE_KEY} Authorization: Bearer ${JWT} ` +
  'cookie=sessionabc123 card=4111111111111111 session 550e8400-e29b-41d4-a716-446655440000 for "Marie Curie"';

export const HOSTILE_STACK = [
  `Error: ${HOSTILE_MESSAGE}`,
  '    at handleOrder (/home/jdupont/app/src/routes/orders/[id]/+page.server.ts:42:11)',
  '    at async Module.load (file:///home/jdupont/app/.svelte-kit/output/server/chunks/DRaQ1Mha.js:10:5)',
  '    at https://app.example.com/_app/immutable/chunks/BcD3f9Xy.js?email=jean.dupont@example.com&uid=48213:1:2345',
  'onClick@https://app.example.com/_app/immutable/entry/app.Cm3x9aBq.js?token=reset-token-9d8c7b#x:3:77',
].join('\n');

/** An Error-like object carrying every forbidden field a careless caller might attach. */
export function hostileError() {
  const error = new Error(HOSTILE_MESSAGE);
  error.stack = HOSTILE_STACK;
  Object.assign(error, {
    ip: '203.0.113.42',
    email: 'jean.dupont@example.com',
    userId: '48213',
    user: { id: '48213', email: 'jean.dupont@example.com', name: 'Marie Curie' },
    body: { password: 'hunter2', card: '4111111111111111' },
    cookie: 'sessionabc123',
    headers: { authorization: 'Bearer secret', cookie: 'sessionabc123' },
    url: 'https://app.example.com/orders/48213?email=jean.dupont@example.com',
    query: 'email=jean.dupont@example.com',
  });
  return error;
}

export const CONTEXT = { product: 'klar', env: 'preview', releaseSha: 'ABCDEF0123456789abcdef0123456789abcdef01' };

export function assertNoPii(text) {
  for (const needle of PII_NEEDLES) {
    if (text.includes(needle)) throw new Error(`PII needle leaked: ${needle}\n${text}`);
  }
}
