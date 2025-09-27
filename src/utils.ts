import fs from 'node:fs';
import { readdir, readFile, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { checkbox, password as promptPassword, select } from '@inquirer/prompts';
import envPaths from 'env-paths';
import _sodium from 'libsodium-wrappers-sumo';
import { EncBundleSchema, type Entry, type EntryMetadata } from './schemas';

// App-specific paths for config and data storage
const paths = envPaths('priv-journal');

export const init = async () => {
  try {
    // TODO: check if it's already initialized. If not, continue
    // TODO: if it's already initialized, show the user double confirmation to re-initialize, letting them know that the old entries will be lost (?)

    console.log('Initializing private journal...');

    await _sodium.ready;
    const sodium = _sodium;

    const keypair = sodium.crypto_box_keypair();
    const publicKey = keypair.publicKey;
    const privateKey = keypair.privateKey;

    console.info(
      "Store your password somewhere safe. You'll need it to decrypt your journal. If you lose it, nobody can help you recover it."
    );

    const password = await promptPassword({
      message: 'Set an encryption password',
      mask: true,
      validate: (input) => (input && input.length >= 8 ? true : 'Use at least 8 characters'),
    });
    const passwordConfirmation = await promptPassword({
      message: 'Confirm your encryption password',
      mask: true,
      validate: (input) => (input && input.length >= 8 ? true : 'Use at least 8 characters'),
    });

    if (password !== passwordConfirmation) {
      console.error('Passwords do not match');
      process.exit(1);
    }

    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    // Derive a key for XChaCha20-Poly1305-ietf
    const key = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      password,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    // Nonce for XChaCha20-Poly1305-ietf (24 bytes)
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Encrypt the private key (no additional data)
    const encryptedPrivKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(privateKey, null, null, nonce, key);

    // Ensure config directory exists
    if (!fs.existsSync(paths.config)) {
      fs.mkdirSync(paths.config, { recursive: true });
    }

    const pubKeyPath = path.resolve(paths.config, 'pubkey.bin');
    const privEncPath = path.resolve(paths.config, 'privkey.enc');
    const configPath = path.resolve(paths.config, 'config.json');

    // Write raw public key bytes
    await writeFile(pubKeyPath, Buffer.from(publicKey));

    // Write encrypted private key bundle as JSON (salt, nonce, ciphertext)
    const encBundle = {
      version: '1',
      cipher: {
        alg: 'xchacha20poly1305-ietf',
        nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
        ciphertext: sodium.to_base64(encryptedPrivKey, sodium.base64_variants.ORIGINAL),
      },
      kdf: {
        alg: 'argon2id13',
        keyBytes: sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        opslimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        memlimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        salt: sodium.to_base64(salt, sodium.base64_variants.ORIGINAL),
      },
    } as const;
    await writeFile(privEncPath, Buffer.from(JSON.stringify(encBundle, null, 2)));

    // Write config metadata
    const config = {
      version: '0.1.0',
      createdAt: new Date().toISOString(),
      keypair: {
        scheme: 'crypto_box/curve25519-xchacha20-poly1305',
        publicKeyFile: path.basename(pubKeyPath),
        privateKeyFile: path.basename(privEncPath),
        publicKeyFormat: 'raw',
        privateKeyFormat: 'enc-json',
      },
      kdf: {
        alg: 'argon2id13',
        opslimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        memlimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      },
    } as const;
    await writeFile(configPath, Buffer.from(JSON.stringify(config, null, 2)));

    return { pubKeyPath, privEncPath, configPath };
  } catch (error) {
    console.error('Error during initialization:', error);
    process.exit(1);
  }
};

export const getKeys = async (password: string) => {
  await _sodium.ready;
  const sodium = _sodium;

  const pubKeyPath = path.resolve(paths.config, 'pubkey.bin');
  const privEncPath = path.resolve(paths.config, 'privkey.enc');

  let publicKey: Uint8Array;
  try {
    publicKey = new Uint8Array(await readFile(pubKeyPath));
  } catch {
    console.log('Not initialized, initializing...');
    await init();
    publicKey = new Uint8Array(await readFile(pubKeyPath));
  }

  const encJson = EncBundleSchema.parse(JSON.parse(await readFile(privEncPath, 'utf-8')));

  const salt = sodium.from_base64(encJson.kdf.salt, sodium.base64_variants.ORIGINAL);
  const key = sodium.crypto_pwhash(
    encJson.kdf.keyBytes,
    password,
    salt,
    encJson.kdf.opslimit,
    encJson.kdf.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );

  const nonce = sodium.from_base64(encJson.cipher.nonce, sodium.base64_variants.ORIGINAL);
  const ciphertext = sodium.from_base64(encJson.cipher.ciphertext, sodium.base64_variants.ORIGINAL);
  const privateKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key);

  return { publicKey, privateKey };
};

export const getEntries = async (password: string) => {
  await _sodium.ready;
  const sodium = _sodium;

  const { publicKey, privateKey } = await getKeys(password);
  const entriesDir = path.resolve(paths.data);

  if (!fs.existsSync(entriesDir)) {
    return [];
  }

  const files = (await readdir(entriesDir))
    .filter((f) => !f.startsWith('.'))
    .sort()
    .reverse();

  const entries: Entry[] = [];

  for (const file of files) {
    const full = path.join(entriesDir, file);
    const stats = await fs.promises.stat(full);
    const date = stats.mtime;
    const contentB64 = (await readFile(full, 'utf-8')).trim();

    if (!contentB64) {
      entries.push({
        filename: file,
        text: '',
        preview: '',
        date,
        metadata: {},
      });
      continue;
    }

    const sealed = sodium.from_base64(contentB64, sodium.base64_variants.ORIGINAL);
    const opened = sodium.crypto_box_seal_open(sealed, publicKey, privateKey);

    const text = Buffer.from(opened).toString('utf-8');

    // Parse metadata and content
    const { metadata, content } = parseMetadata(text);
    const preview = content.length > 150 ? `${content.substring(0, 150)}...` : content;

    entries.push({
      filename: file,
      text,
      preview,
      date,
      metadata,
    });
  }

  return entries;
};

// Function overloads for type inference
export function selectEntries(entries: Entry[]): Promise<string>;
export function selectEntries(entries: Entry[], opts: { multiple: false }): Promise<string>;
export function selectEntries(entries: Entry[], opts: { multiple: true }): Promise<string[]>;
export function selectEntries(entries: Entry[], opts?: { multiple?: boolean }): Promise<string | string[]>;

// Implementation
export async function selectEntries(entries: Entry[], opts?: { multiple?: boolean }): Promise<string | string[]> {
  if (entries.length === 0) {
    throw new Error('No entries found');
  }

  const choices = [];

  for (const entry of entries) {
    if (!entry.text) continue;

    // Parse content to show only the actual content (without metadata header) in preview
    const { content } = parseMetadata(entry.text);
    const preview = content.length > 60 ? `${content.substring(0, 60)}...` : content;

    choices.push({
      name: preview,
      value: entry.filename,
    });
  }

  const multiple = opts?.multiple ?? false;

  if (multiple) {
    const selectedEntries = await checkbox({
      message: 'Select journal entries:',
      choices: choices,
      pageSize: 10,
    });
    return selectedEntries;
  } else {
    const selectedEntry = await select({
      message: 'Select a journal entry:',
      choices: choices,
      pageSize: 10,
    });
    return selectedEntry;
  }
}

export const getPasswordWithRetry = async (): Promise<string> => {
  while (true) {
    try {
      const password = await promptPassword({
        message: 'Enter your password',
        mask: true,
      });

      await getKeys(password);
      return password;
    } catch {
      console.error('Incorrect password. Please try again.');
    }
  }
};

export const editEntry = async (filename: string, newText: string) => {
  await _sodium.ready;
  const sodium = _sodium;

  const pubKeyPath = path.resolve(paths.config, 'pubkey.bin');
  const entriesDir = path.resolve(paths.data);

  if (!fs.existsSync(pubKeyPath)) {
    throw new Error(`Missing public key at ${pubKeyPath}. Run 'init' first.`);
  }

  const publicKey = new Uint8Array(await readFile(pubKeyPath));

  const messageBytes = new TextEncoder().encode(newText);
  const sealed = sodium.crypto_box_seal(messageBytes, publicKey);
  const sealedB64 = sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL);

  // Write to the same file path
  const filepath = path.join(entriesDir, filename);
  await writeFile(filepath, `${sealedB64}\n`);
};

export const getEntryCount = async () => {
  const entriesDir = path.resolve(paths.data);

  if (!fs.existsSync(entriesDir)) {
    return 0;
  }

  const files = (await readdir(entriesDir)).filter((f) => !f.startsWith('.'));

  return files.length;
};

export const deleteEntries = async (filenames: string[]) => {
  const entriesDir = path.resolve(paths.data);
  let deletedCount = 0;

  for (const filename of filenames) {
    try {
      const filepath = path.join(entriesDir, filename);
      await unlink(filepath);
      deletedCount++;
    } catch (error) {
      console.error(`Failed to delete ${filename}:`, error);
    }
  }

  return deletedCount;
};

// Metadata utility functions
export const parseMetadata = (text: string): { metadata: EntryMetadata; content: string } => {
  const parts = text.split('---');

  if (parts.length < 2) {
    // No metadata, extract tags from content only
    const tags = extractTagsFromText(text);
    return {
      metadata: tags.length > 0 ? { tags } : {},
      content: text,
    };
  }

  const metadataText = parts[0].trim();
  const content = parts.slice(1).join('---').trim();
  const metadata: EntryMetadata = {};

  // Parse category
  const categoryMatch = metadataText.match(/^category:\s*(@\w+)$/m);
  if (categoryMatch) {
    metadata.category = categoryMatch[1];
  }

  // Parse tags from metadata
  const tagsMatch = metadataText.match(/^tags:\s*(.+)$/m);
  let metadataTags: string[] = [];
  if (tagsMatch) {
    metadataTags = tagsMatch[1].split(/\s+/).filter((tag) => tag.startsWith('#'));
  }

  // Extract tags from content
  const contentTags = extractTagsFromText(content);

  // Combine and deduplicate tags
  const allTags = [...new Set([...metadataTags, ...contentTags])];
  if (allTags.length > 0) {
    metadata.tags = allTags;
  }

  return { metadata, content };
};

export const formatEntryWithMetadata = (content: string, metadata: EntryMetadata): string => {
  if (!metadata.category && (!metadata.tags || metadata.tags.length === 0)) {
    return content;
  }

  const metadataLines: string[] = [];

  if (metadata.category) {
    metadataLines.push(`category: ${metadata.category}`);
  }

  if (metadata.tags && metadata.tags.length > 0) {
    metadataLines.push(`tags: ${metadata.tags.join(' ')}`);
  }

  return `${metadataLines.join('\n')}\n---\n${content}`;
};

export const extractTagsFromText = (text: string): string[] => {
  const tagRegex = /#\w+/g;
  const matches = text.match(tagRegex);
  return matches ? [...new Set(matches)] : [];
};

export const extractCategoryFromArgs = (args: string[]): { category?: string; remainingArgs: string[] } => {
  const categoryIndex = args.findIndex((arg) => arg.startsWith('@'));

  if (categoryIndex === -1) {
    return { remainingArgs: args };
  }

  const category = args[categoryIndex];
  const remainingArgs = args.filter((_, index) => index !== categoryIndex);

  return { category, remainingArgs };
};
