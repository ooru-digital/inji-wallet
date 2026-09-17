/**
 * Used only when Pixelpass of the full VC exceeds QR capacity.
 * Display still uses the original VC. The QR omits inlined blobs that cannot fit.
 */
export const MAX_QR_FIELD_CHARS = 2048;

export function compactVcForQr(credential: unknown): string {
  if (typeof credential === 'string') {
    return credential;
  }
  if (credential == null || typeof credential !== 'object') {
    return JSON.stringify(credential);
  }

  const clone = JSON.parse(JSON.stringify(credential));
  compactNode(clone);
  return JSON.stringify(clone);
}

function shouldStrip(value: string): boolean {
  if (value.startsWith('data:')) {
    return true;
  }
  if (value.startsWith('http://') || value.startsWith('https://')) {
    return false;
  }
  return value.length > MAX_QR_FIELD_CHARS;
}

function compactNode(node: unknown): void {
  if (Array.isArray(node)) {
    node.forEach((item, index) => {
      if (typeof item === 'string') {
        if (shouldStrip(item)) {
          node[index] = '';
        }
      } else if (item && typeof item === 'object') {
        compactNode(item);
      }
    });
    return;
  }

  if (!node || typeof node !== 'object') {
    return;
  }

  const record = node as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    const value = record[key];
    if (key === 'renderMethod') {
      delete record[key];
      continue;
    }
    if (typeof value === 'string') {
      if (shouldStrip(value)) {
        delete record[key];
      }
      continue;
    }
    if (value && typeof value === 'object') {
      compactNode(value);
    }
  }
}
