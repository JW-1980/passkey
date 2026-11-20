import { describe, expect, it } from 'vitest';
import { handoffDeniedUrl, readHandoffRequest } from '../src/handoff.js';

const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const STATE = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const QUERY = `challenge=${CHALLENGE}&port=51234&state=${STATE}`;
const EXPECTED = { challenge: CHALLENGE, port: 51234, state: STATE };

describe('readHandoffRequest', () => {
  it('reads the request from the query', () => {
    expect(readHandoffRequest(`https://app.example/desktop-sign-in?${QUERY}`)).toEqual(EXPECTED);
    expect(readHandoffRequest(new URL(`https://app.example/in?x=1&${QUERY}`))).toEqual(EXPECTED);
  });

  it('reads the request from behind a hash route', () => {
    expect(readHandoffRequest(`https://app.example/#/desktop-sign-in?${QUERY}`)).toEqual(EXPECTED);
  });

  it.each([
    'not a url',
    'https://app.example/in',
    `https://app.example/in?challenge=${CHALLENGE}&port=51234`,
    `https://app.example/in?${QUERY}&state=${STATE}`,
    `https://app.example/in?challenge=short&port=51234&state=${STATE}`,
    `https://app.example/in?challenge=${CHALLENGE}&port=51234&state=${STATE}%3Cscript%3E`,
    `https://app.example/in?challenge=${CHALLENGE}&port=80&state=${STATE}`,
    `https://app.example/in?challenge=${CHALLENGE}&port=1023&state=${STATE}`,
    `https://app.example/in?challenge=${CHALLENGE}&port=65536&state=${STATE}`,
    `https://app.example/in?challenge=${CHALLENGE}&port=51234x&state=${STATE}`,
    `https://app.example/in?challenge=${CHALLENGE}&port=5.1e4&state=${STATE}`,
  ])('returns null for %s', (address) => {
    expect(readHandoffRequest(address)).toBeNull();
  });

  it('accepts the edges of the port range', () => {
    expect(readHandoffRequest(`https://a.example/?challenge=${CHALLENGE}&port=1024&state=${STATE}`)?.port).toBe(1024);
    expect(readHandoffRequest(`https://a.example/?challenge=${CHALLENGE}&port=65535&state=${STATE}`)?.port).toBe(65535);
  });
});

describe('handoffDeniedUrl', () => {
  it('points at the loopback callback of the desktop app', () => {
    expect(handoffDeniedUrl(EXPECTED)).toBe(`http://127.0.0.1:51234/callback?error=denied&state=${STATE}`);
    expect(handoffDeniedUrl(EXPECTED, '/terug')).toBe(`http://127.0.0.1:51234/terug?error=denied&state=${STATE}`);
  });
});
