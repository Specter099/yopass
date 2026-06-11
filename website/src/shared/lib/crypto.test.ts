import { describe, expect, it } from 'vitest';
import { decryptMessage, encryptMessage } from './crypto';

describe('encryptMessage / decryptMessage', () => {
  it('round-trips a text secret', async () => {
    const secret = 'a very secret message';
    const password = 'correct horse battery staple';

    const armored = (await encryptMessage(secret, password)) as string;
    const decrypted = await decryptMessage(armored, password, 'utf8');

    expect(decrypted.data).toBe(secret);
  });

  it('produces an armored PGP message', async () => {
    const armored = (await encryptMessage('hello', 'pw')) as string;
    expect(armored).toContain('-----BEGIN PGP MESSAGE-----');
    expect(armored).toContain('-----END PGP MESSAGE-----');
  });

  it('does not contain the plaintext or password in the ciphertext', async () => {
    const armored = (await encryptMessage(
      'plaintext-marker',
      'password-marker',
    )) as string;
    expect(armored).not.toContain('plaintext-marker');
    expect(armored).not.toContain('password-marker');
  });

  it('rejects decryption with the wrong password', async () => {
    const armored = (await encryptMessage('secret', 'right')) as string;
    await expect(decryptMessage(armored, 'wrong', 'utf8')).rejects.toThrow();
  });

  it('rejects garbage input', async () => {
    await expect(
      decryptMessage('not a pgp message', 'pw', 'utf8'),
    ).rejects.toThrow();
  });

  it('round-trips unicode content', async () => {
    const secret = 'pässwörd 密码 🔐';
    const armored = (await encryptMessage(secret, 'pw')) as string;
    const decrypted = await decryptMessage(armored, 'pw', 'utf8');
    expect(decrypted.data).toBe(secret);
  });
});
