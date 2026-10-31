/**
 * Pin for `getStatus` honoring `any_of` auth alternatives (src/commands/integrations.ts).
 *
 * The flat frontmatter `secrets:` list conflates alternative auth paths: an any_of
 * recipe lists CLAWVISOR_URL, CLAWVISOR_AGENT_TOKEN, GOOGLE_CLIENT_ID and
 * GOOGLE_CLIENT_SECRET, but the user only needs ONE path (Option A ClawVisor OR
 * Option B Google). The old all-secrets-required check reported a correctly
 * configured single-path user as "available", contradicting `gbrain features`,
 * which already treats these as any-of. getStatus now honors the recipe's own
 * any_of health check.
 *
 * Recipes WITHOUT an any_of group must keep the original all-secrets-required rule.
 */
import { describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { branchSatisfiedByEnv, checkSecrets, executeHealthCheck, getStatus, parseRecipe } from '../src/commands/integrations.ts';
import { openVault, vaultEnvKeysFromMetas } from '../src/core/creds/vault.ts';
import { withEnv } from './helpers/with-env.ts';

const REPO_ROOT = join(import.meta.dir, '..');
const recipe = (id: string) => {
  const content = readFileSync(join(REPO_ROOT, 'recipes', `${id}.md`), 'utf-8');
  const parsed = parseRecipe(content, `${id}.md`);
  if (!parsed) throw new Error(`failed to parse ${id}`);
  return parsed;
};

// Every env var these recipes read. Each test controls the whole surface through
// withEnv (rule R1: no direct process.env mutation) so leftover env or host
// ~/.gbrain files can't leak in.
const CLEARED: Record<string, undefined> = {
  CLAWVISOR_URL: undefined, CLAWVISOR_AGENT_TOKEN: undefined, GOOGLE_CLIENT_ID: undefined,
  GOOGLE_CLIENT_SECRET: undefined, X_HANDLE: undefined, X_API_BEARER_TOKEN: undefined,
  OPENAI_API_KEY: undefined,
};

async function withIsolatedHome<T>(
  overrides: Record<string, string | undefined>,
  fn: (gbrainHome: string) => T | Promise<T>,
): Promise<T> {
  const gbrainHome = mkdtempSync(join(tmpdir(), 'gbrain-int-vault-'));
  try {
    return await withEnv({ ...CLEARED, GBRAIN_HOME: gbrainHome, ...overrides }, () => fn(gbrainHome));
  } finally {
    rmSync(gbrainHome, { recursive: true, force: true });
  }
}

describe('getStatus honors any_of auth alternatives', () => {
  test('calendar-to-brain: no secrets → available', async () => {
    await withIsolatedHome({}, () => {
      expect(getStatus(recipe('calendar-to-brain'))).toBe('available');
    });
  });

  test('calendar-to-brain: ClawVisor path (Option A) alone → configured', async () => {
    // The recommended path: URL + agent token, no Google OAuth. The old all-of
    // rule returned "available" here because GOOGLE_CLIENT_ID/SECRET were unset.
    await withIsolatedHome({
      CLAWVISOR_URL: 'https://clawvisor.example', CLAWVISOR_AGENT_TOKEN: 'tok',
    }, () => {
      expect(getStatus(recipe('calendar-to-brain'))).toBe('configured');
    });
  });

  test('calendar-to-brain: Google path (Option B) alone → configured', async () => {
    await withIsolatedHome({ GOOGLE_CLIENT_ID: 'gid' }, () => {
      expect(getStatus(recipe('calendar-to-brain'))).toBe('configured');
    });
  });
});

describe('getStatus keeps all-secrets rule for non-any_of recipes', () => {
  test('x-to-brain: partial secrets → available', async () => {
    await withIsolatedHome({ X_API_BEARER_TOKEN: 'tok' }, () => {
      // X_HANDLE still missing
      expect(getStatus(recipe('x-to-brain'))).toBe('available');
    });
  });

  test('x-to-brain: all secrets → configured', async () => {
    await withIsolatedHome({ X_API_BEARER_TOKEN: 'tok', X_HANDLE: 'me' }, () => {
      expect(getStatus(recipe('x-to-brain'))).toBe('configured');
    });
  });
});

describe('vault-backed OAuth/API credentials satisfy integration readiness', () => {
  test('Google OAuth credential in vault.list() marks any_of Google recipes configured', async () => {
    await withIsolatedHome({}, async () => {
      const vault = openVault();
      await vault.put({
        id: 'google:user@example.com',
        provider: 'google',
        kind: 'oauth2',
        client_ref: 'hosted-relay',
        secret: { access_token: 'ya29.redacted', refresh_token: '1//redacted' },
        meta: { account: 'user@example.com', connected_at: '2026-10-31T00:00:00.000Z' },
      });

      const metas = await vault.list();
      const keys = vaultEnvKeysFromMetas(metas);
      expect(keys.has('GOOGLE_CLIENT_ID')).toBe(true);
      expect(
        branchSatisfiedByEnv({ type: 'env_exists', name: 'GOOGLE_CLIENT_ID', label: 'Google OAuth' }, {}, keys),
      ).toBe(true);
      expect(getStatus(recipe('calendar-to-brain'))).toBe('configured');
      expect(getStatus(recipe('email-to-brain'))).toBe('configured');

      const hc = await executeHealthCheck(
        { type: 'env_exists', name: 'GOOGLE_CLIENT_ID', label: 'Google OAuth' },
        'calendar-to-brain',
        true,
      );
      expect(hc.status).toBe('ok');
    });
  });

  test('API-key and bearer credentials in vault satisfy non-any_of recipes without false positives', async () => {
    await withIsolatedHome({}, async () => {
      const vault = openVault();
      await vault.put({
        id: 'openai:default',
        provider: 'openai',
        kind: 'api_key',
        client_ref: 'byo',
        secret: { token: 'sk-test-redacted' },
        meta: { connected_at: '2026-10-31T00:00:00.000Z' },
      });
      await vault.put({
        id: 'x:default',
        provider: 'x',
        kind: 'bearer',
        client_ref: 'byo',
        secret: { token: 'x-bearer-redacted' },
        meta: { connected_at: '2026-10-31T00:00:00.000Z' },
      });

      expect(getStatus(recipe('agent-voice'))).toBe('configured');
      expect(checkSecrets([{ name: 'OPENAI_API_KEY', description: 'OpenAI', where: 'https://platform.openai.com' }]).set)
        .toEqual(['OPENAI_API_KEY']);
      // X_HANDLE is still unset, so x-to-brain must remain 'available'.
      expect(getStatus(recipe('x-to-brain'))).toBe('available');
    });

    await withIsolatedHome({ X_HANDLE: 'alice_example' }, async () => {
      const vault = openVault();
      await vault.put({
        id: 'x:default',
        provider: 'x',
        kind: 'bearer',
        client_ref: 'byo',
        secret: { token: 'x-bearer-redacted' },
        meta: { connected_at: '2026-10-31T00:00:00.000Z' },
      });

      expect(getStatus(recipe('x-to-brain'))).toBe('configured');
    });
  });
});
