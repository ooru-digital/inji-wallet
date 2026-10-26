import {resolvePortraitImages} from './compressFaceImage';

// A PNG's first bytes, as base64.
const PNG_BASE64 = Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]).toString(
  'base64',
);

const respondWith = (response: Partial<Response>) =>
  jest.fn().mockResolvedValue({ok: true, status: 200, ...response});

const pngBlob = {size: 7, type: 'image/png'};

class FakeFileReader {
  result: string | null = null;
  error: Error | null = null;
  onloadend: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readAsDataURL() {
    this.result = `data:image/png;base64,${PNG_BASE64}`;
    this.onloadend?.();
  }
}

describe('resolvePortraitImages', () => {
  const originalFetch = global.fetch;
  const originalFileReader = (global as any).FileReader;

  beforeEach(() => {
    (global as any).FileReader = FakeFileReader;
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    global.fetch = originalFetch;
    (global as any).FileReader = originalFileReader;
    jest.restoreAllMocks();
  });

  it('passes image data through without downloading', async () => {
    global.fetch = jest.fn();
    const dataUri = `data:image/png;base64,${PNG_BASE64}`;

    await expect(resolvePortraitImages([dataUri, PNG_BASE64])).resolves.toEqual(
      [dataUri, PNG_BASE64],
    );
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('downloads a photo given as an https link', async () => {
    global.fetch = respondWith({blob: async () => pngBlob as any});

    await expect(
      resolvePortraitImages(['https://storage.example/photo.png']),
    ).resolves.toEqual([PNG_BASE64]);
    expect(global.fetch).toHaveBeenCalledWith(
      'https://storage.example/photo.png',
      expect.anything(),
    );
  });

  it('leaves out a link that cannot be downloaded', async () => {
    global.fetch = respondWith({ok: false, status: 403});

    await expect(
      resolvePortraitImages(['https://storage.example/expired.png']),
    ).resolves.toEqual([]);
  });

  it('leaves out a photo that is too large', async () => {
    global.fetch = respondWith({
      blob: async () => ({size: 6 * 1024 * 1024, type: 'image/png'} as any),
    });

    await expect(
      resolvePortraitImages(['https://storage.example/huge.png']),
    ).resolves.toEqual([]);
  });

  it('does not download plain http links', async () => {
    global.fetch = jest.fn();

    await expect(
      resolvePortraitImages(['http://storage.example/photo.png']),
    ).resolves.toEqual(['http://storage.example/photo.png']);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
