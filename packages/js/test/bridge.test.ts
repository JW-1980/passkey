import { describe, expect, it } from 'vitest';
import { bridgeAuthenticator, fromBridgeError } from '../src/bridge.js';

const ATTESTATION = { id: 'aWQ', rawId: 'aWQ', response: { clientDataJSON: 'a', attestationObject: 'b' } };
const ASSERTION = { id: 'aWQ', rawId: 'aWQ', response: { clientDataJSON: 'a', authenticatorData: 'b', signature: 'c', userHandle: 'dQ' } };

function bridge(result: unknown, supported: boolean | Promise<boolean> = true) {
  const seen: object[] = [];
  const answer = async (options: object) => {
    seen.push(options);
    if (result instanceof Error || (typeof result === 'object' && result !== null && 'throw' in result)) {
      throw (result as { throw?: unknown }).throw ?? result;
    }
    return result;
  };
  return { seen, isSupported: () => supported, create: answer, get: answer };
}

describe('bridgeAuthenticator', () => {
  it('accepts an object result and fills in the credential type', async () => {
    const native = bridge(ATTESTATION);
    const options = { challenge: 'x' } as never;
    await expect(bridgeAuthenticator(native).create(options)).resolves.toEqual({ ...ATTESTATION, type: 'public-key' });
    expect(native.seen).toEqual([options]);
  });

  it('accepts the JSON text Android returns', async () => {
    await expect(bridgeAuthenticator(bridge(JSON.stringify(ASSERTION))).get({ challenge: 'x' })).resolves.toEqual({
      ...ASSERTION,
      type: 'public-key',
    });
  });

  it.each([
    ['not json', 'create'],
    [null, 'create'],
    [[], 'create'],
    [{ id: 'aWQ', rawId: 'aWQ' }, 'create'],
    [{ ...ATTESTATION, response: { clientDataJSON: 'a' } }, 'create'],
    [ATTESTATION, 'get'],
    [{ ...ASSERTION, id: 7 }, 'get'],
  ] as const)('refuses the unusable result %j of %s', async (result, method) => {
    const authenticator = bridgeAuthenticator(bridge(result));
    const attempt = method === 'create' ? authenticator.create({} as never) : authenticator.get({ challenge: 'x' });
    await expect(attempt).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('reports support from a sync or async bridge and never offers autofill', async () => {
    await expect(bridgeAuthenticator(bridge(null, false)).isSupported()).resolves.toBe(false);
    await expect(bridgeAuthenticator(bridge(null, Promise.resolve(true))).isSupported()).resolves.toBe(true);
    await expect(bridgeAuthenticator(bridge(null)).supportsAutofill()).resolves.toBe(false);
  });

  it('refuses autofill without calling the bridge', async () => {
    const native = bridge(ASSERTION);
    await expect(bridgeAuthenticator(native).get({ challenge: 'x' }, { autofill: true })).rejects.toMatchObject({ code: 'unsupported' });
    expect(native.seen).toEqual([]);
  });

  it('translates errors the bridge throws', async () => {
    const native = bridge({ throw: { error: 'UserCancelled', message: 'The user cancelled the request.' } });
    await expect(bridgeAuthenticator(native).get({ challenge: 'x' })).rejects.toMatchObject({
      code: 'cancelled',
      message: 'The user cancelled the request.',
    });
  });
});

describe('fromBridgeError', () => {
  it.each([
    [{ error: 'UserCancelled' }, 'cancelled'],
    [{ error: 'TimedOut' }, 'cancelled'],
    [{ error: 'NotSupported' }, 'unsupported'],
    [{ error: 'NoCredentials' }, 'no_credentials'],
    [{ error: 'CredentialAlreadyExists' }, 'already_registered'],
    [{ error: 'BadConfiguration' }, 'security'],
    [{ error: 'RequestFailed' }, 'unknown'],
    [{ code: 'cancelled' }, 'cancelled'],
    [{ code: 'already_registered' }, 'already_registered'],
    [{ code: 'E_SOMETHING_ELSE' }, 'unknown'],
    ['plain text', 'unknown'],
    [null, 'unknown'],
  ])('maps %j to %s', (thrown, code) => {
    const error = fromBridgeError(thrown);
    expect(error.code).toBe(code);
    expect(error.cause).toBe(thrown);
  });
});
