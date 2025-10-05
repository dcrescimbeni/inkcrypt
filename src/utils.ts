import fs from 'node:fs';
import { readdir, readFile, unlink, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { checkbox, password as promptPassword, select } from '@inquirer/prompts';
import envPaths from 'env-paths';
import _sodium from 'libsodium-wrappers-sumo';
import { EncBundleSchema, type Entry, type EntryMetadata } from './schemas.js';

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

export const changePassword = async () => {
  try {
    await _sodium.ready;
    const sodium = _sodium;

    const currentPassword = await getPasswordWithRetry();
    const { publicKey: oldPublicKey, privateKey: oldPrivateKey } = await getKeys(currentPassword);

    const entriesDir = path.resolve(paths.data);
    const entryPayloads: Array<{
      filename: string;
      plaintext: string;
      originalContent: string;
      atime: Date;
      mtime: Date;
    }> = [];

    if (fs.existsSync(entriesDir)) {
      const files = (await readdir(entriesDir)).filter((f) => !f.startsWith('.')).sort();

      for (const file of files) {
        const fullPath = path.join(entriesDir, file);
        const stats = await fs.promises.stat(fullPath);
        const rawContent = await readFile(fullPath, 'utf-8');
        const contentB64 = rawContent.trim();

        let plaintext = '';
        if (contentB64) {
          const sealed = sodium.from_base64(contentB64, sodium.base64_variants.ORIGINAL);
          const opened = sodium.crypto_box_seal_open(sealed, oldPublicKey, oldPrivateKey);
          plaintext = Buffer.from(opened).toString('utf-8');
        }

        entryPayloads.push({
          filename: file,
          plaintext,
          originalContent: rawContent,
          atime: stats.atime,
          mtime: stats.mtime,
        });
      }
    }

    const newPassword = await promptPassword({
      message: 'Enter a new encryption password',
      mask: true,
      validate: (input) => (input && input.length >= 1 ? true : 'Password cannot be empty'),
    });

    const newPasswordConfirmation = await promptPassword({
      message: 'Confirm the new encryption password',
      mask: true,
      validate: (input) => (input && input.length >= 1 ? true : 'Password cannot be empty'),
    });

    if (newPassword !== newPasswordConfirmation) {
      console.error('Passwords do not match');
      process.exit(1);
    }

    const newKeypair = sodium.crypto_box_keypair();
    const newPublicKey = newKeypair.publicKey;
    const newPrivateKey = newKeypair.privateKey;

    const reencryptedEntries = entryPayloads.map((entry) => {
      const messageBytes = new TextEncoder().encode(entry.plaintext);
      const sealed = sodium.crypto_box_seal(messageBytes, newPublicKey);
      const sealedB64 = sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL);
      return {
        ...entry,
        newContent: `${sealedB64}\n`,
      };
    });

    const pubKeyPath = path.resolve(paths.config, 'pubkey.bin');
    const privEncPath = path.resolve(paths.config, 'privkey.enc');
    const configPath = path.resolve(paths.config, 'config.json');

    if (!fs.existsSync(paths.config)) {
      fs.mkdirSync(paths.config, { recursive: true });
    }

    const originalPubKey = fs.existsSync(pubKeyPath) ? await readFile(pubKeyPath) : undefined;
    const originalPrivEnc = fs.existsSync(privEncPath) ? await readFile(privEncPath) : undefined;
    const originalConfig = fs.existsSync(configPath) ? await readFile(configPath, 'utf-8') : undefined;

    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const derivedKey = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      newPassword,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const encryptedPrivKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(newPrivateKey, null, null, nonce, derivedKey);

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

    let parsedConfig: Record<string, unknown> = {};
    if (originalConfig) {
      try {
        parsedConfig = JSON.parse(originalConfig) as Record<string, unknown>;
      } catch {
        parsedConfig = {};
      }
    }

    const now = new Date().toISOString();
    const parsedVersion = (parsedConfig as { version?: unknown }).version;
    const parsedCreatedAt = (parsedConfig as { createdAt?: unknown }).createdAt;
    const version = typeof parsedVersion === 'string' ? parsedVersion : '0.1.0';
    const createdAt = typeof parsedCreatedAt === 'string' ? parsedCreatedAt : now;

    const updatedConfig: Record<string, unknown> = {
      ...parsedConfig,
      version,
      createdAt,
      updatedAt: now,
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
    };

    try {
      await writeFile(pubKeyPath, Buffer.from(newPublicKey));
      await writeFile(privEncPath, Buffer.from(JSON.stringify(encBundle, null, 2)));
      await writeFile(configPath, Buffer.from(JSON.stringify(updatedConfig, null, 2)));

      if (!fs.existsSync(entriesDir)) {
        fs.mkdirSync(entriesDir, { recursive: true });
      }

      for (const entry of reencryptedEntries) {
        const targetPath = path.join(entriesDir, entry.filename);
        await writeFile(targetPath, entry.newContent);
        await utimes(targetPath, entry.atime, entry.mtime);
      }

      console.log('Password updated successfully.');
    } catch (error) {
      if (originalPubKey) {
        await writeFile(pubKeyPath, originalPubKey);
      }
      if (originalPrivEnc) {
        await writeFile(privEncPath, originalPrivEnc);
      }
      if (originalConfig !== undefined) {
        await writeFile(configPath, Buffer.from(originalConfig));
      }

      for (const entry of entryPayloads) {
        const targetPath = path.join(entriesDir, entry.filename);
        await writeFile(targetPath, entry.originalContent);
        await utimes(targetPath, entry.atime, entry.mtime);
      }

      console.error('Failed to change password. Original state restored.');
      throw error;
    }
  } catch (error) {
    console.error('Failed to change password:', error);
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

export const getEntries = async (
  {
    password,
    category,
    tags
  }: {
    password: string,
    category?: string,
    tags?: string[]
  }) => {
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

    const entry = {
      filename: file,
      text,
      preview,
      date,
      metadata,
    };

    // Apply filters if provided
    let includeEntry = true;

    // Category filter
    if (category && metadata.category !== category) {
      includeEntry = false;
    }

    // Tag filter
    if (includeEntry && tags && tags.length > 0) {
      includeEntry = entryMatchesTags(entry, tags);
    }

    if (includeEntry) {
      entries.push(entry);
    }
  }


  if (entries.length === 0) {
    const filters = [];
    if (category) filters.push(`category ${category}`);
    if (tags && tags.length > 0) filters.push(`tags ${tags.join(', ')}`);

    if (filters.length > 0) {
      console.error(`No entries found for ${filters.join(' and ')}.`);
    } else {
      console.error('No entries found.');
    }
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
    } catch (error) {
      if (
        error instanceof Error &&
        (error.name === 'ExitPromptError' || error.name === 'CancelPromptError' || error.name === 'AbortPromptError')
      ) {
        console.log('Password prompt cancelled.');
        process.exit(0);
      }
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

export const getEntryCount = async (
  {
    password,
    category,
    tags
  }: {
    password?: string,
    category?: string,
    tags?: string[]
  }) => {
  if (!category && (!tags || tags.length === 0)) {
    // If no filters, use the fast file count method
    const entriesDir = path.resolve(paths.data);

    if (!fs.existsSync(entriesDir)) {
      return 0;
    }

    const files = (await readdir(entriesDir)).filter((f) => !f.startsWith('.'));

    return files.length;
  }

  // If any filter is provided, we need to decrypt and check metadata
  if (!password) {
    throw new Error('Password required when filtering by category or tags');
  }

  const entries = await getEntries({ password, category, tags });
  return entries.length;
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

export const normalizeTag = (tag: string): string => {
  return tag.startsWith('#') ? tag : `#${tag}`;
};

export const normalizeTags = (tags: string[]): string[] => {
  return tags.map(normalizeTag);
};

export const entryMatchesTags = (entry: Entry, requiredTags: string[]): boolean => {
  if (!entry.metadata || !entry.metadata.tags || entry.metadata.tags.length === 0) {
    return false;
  }

  const entryTags = entry.metadata.tags.map(normalizeTag);
  const normalizedRequiredTags = normalizeTags(requiredTags);

  return normalizedRequiredTags.every(tag => entryTags.includes(tag));
};
