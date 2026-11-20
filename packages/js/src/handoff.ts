import type { HandoffRequest } from './client.js';

const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/**
 * Reads the desktop app's handoff request from the address of the browser page: `challenge`,
 * `port` and `state`, either in the query (`/desktop-sign-in?challenge=…`) or behind a hash route
 * (`/#/desktop-sign-in?challenge=…`). Returns `null` when the address holds no valid request; the
 * page must then show an error instead of asking the server for a code.
 */
export function readHandoffRequest(address: string | URL): HandoffRequest | null {
  let url: URL;
  try {
    url = new URL(String(address));
  } catch {
    return null;
  }
  const hashQuery = url.hash.includes('?') ? url.hash.slice(url.hash.indexOf('?') + 1) : '';
  const parameters = url.searchParams.has('challenge') ? url.searchParams : new URLSearchParams(hashQuery);

  const challenge = parameters.getAll('challenge');
  const port = parameters.getAll('port');
  const state = parameters.getAll('state');
  if (challenge.length !== 1 || port.length !== 1 || state.length !== 1) {
    return null;
  }
  const [challengeValue, portText, stateValue] = [challenge[0] ?? '', port[0] ?? '', state[0] ?? ''];
  const portNumber = /^[0-9]{4,5}$/.test(portText) ? Number(portText) : 0;
  if (!TOKEN.test(challengeValue) || !TOKEN.test(stateValue) || portNumber < 1024 || portNumber > 65535) {
    return null;
  }
  return { challenge: challengeValue, port: portNumber, state: stateValue };
}

/** The loopback address that tells the desktop app the person declined. */
export function handoffDeniedUrl(request: HandoffRequest, callbackPath = '/callback'): string {
  return `http://127.0.0.1:${request.port}${callbackPath}?error=denied&state=${encodeURIComponent(request.state)}`;
}
