import {MMKV} from '../storage';

const HOLDER_EMAIL_KEY = 'holderEmail';

export async function getHolderEmail(): Promise<string | null> {
  try {
    const email = await MMKV.getItem(HOLDER_EMAIL_KEY);
    return email?.trim() || null;
  } catch {
    return null;
  }
}

export async function setHolderSession(email: string): Promise<void> {
  await MMKV.setItem(HOLDER_EMAIL_KEY, email.trim());
}

export async function clearHolderSession(): Promise<void> {
  MMKV.removeItem(HOLDER_EMAIL_KEY);
}
