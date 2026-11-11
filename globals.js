// UTF-8 only: `text-encoding` also carries 530 KB of tables for other encodings, which
// TextEncoder never uses. Installs TextEncoder/TextDecoder only where the engine lacks them.
require('fast-text-encoding');
