import { Command } from 'commander';
import fs from 'fs';
import { writeFile, readFile, readdir } from 'fs/promises';
import path from 'path';
import _sodium from 'libsodium-wrappers-sumo';

const JOURNAL_DIR = './priv-jrnl';

const program = new Command();

program
  .name('priv-journal')
  .description('A private journal CLI tool')
  .version('0.1.0');

program
  .command('init')
  .description('Initialize a new keypair and setup encryption')
  .action(async () => {
    try {
      console.log('Initializing private journal...');

      await _sodium.ready;
      const sodium = _sodium;


      const keypair = sodium.crypto_box_keypair();
      const publicKey = keypair.publicKey;
      const privateKey = keypair.privateKey;

      // TODO: Prompt the user securely for a password
      const password = 'password';
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
      const nonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      );

      // Encrypt the private key (no additional data)
      const encryptedPrivKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        privateKey,
        null,
        null,
        nonce,
        key,
      );

      // Persist artifacts to disk
      // const journalDir = path.resolve('/priv-jrnl');
      // await mkdir(journalDir, { recursive: true });

      if (!fs.existsSync(JOURNAL_DIR)) {
        fs.mkdirSync(JOURNAL_DIR);
      }

      const pubKeyPath = path.resolve(JOURNAL_DIR, 'pubkey.bin');
      const privEncPath = path.resolve(JOURNAL_DIR, 'privkey.enc');
      const configPath = path.resolve(JOURNAL_DIR, 'config.json');

      // Write raw public key bytes
      await writeFile(pubKeyPath, Buffer.from(publicKey));

      // Write encrypted private key bundle as JSON (salt, nonce, ciphertext)
      const encBundle = {
        version: '1',
        cipher: {
          alg: 'xchacha20poly1305-ietf',
          nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
          ciphertext: sodium.to_base64(
            encryptedPrivKey,
            sodium.base64_variants.ORIGINAL,
          ),
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

      console.log('Wrote files:');
      console.log(' -', pubKeyPath);
      console.log(' -', privEncPath);
      console.log(' -', configPath);

    } catch (error) {
      console.error('Error during initialization:', error);
      process.exit(1);
    }
  });

program
  .command('hello')
  .description('Say hello world')
  .action(() => {
    console.log('Hello, World!');
  });

program
  .command('read')
  .description('Decrypt and print all journal entries')
  .action(async () => {
    try {
      await _sodium.ready;
      const sodium = _sodium;

      const pubKeyPath = path.resolve(JOURNAL_DIR, 'pubkey.bin');
      const privEncPath = path.resolve(JOURNAL_DIR, 'privkey.enc');
      const entriesDir = path.resolve(JOURNAL_DIR, 'entries');

      // Load public key (raw bytes)
      const publicKey = new Uint8Array(await readFile(pubKeyPath));

      // TODO: I should implement zod to validate the JSON instead of type casting
      // Load encrypted private key bundle
      const encJson = JSON.parse(await readFile(privEncPath, 'utf-8')) as {
        version: string;
        cipher: { alg: string; nonce: string; ciphertext: string };
        kdf: {
          alg: string;
          keyBytes: number;
          opslimit: number;
          memlimit: number;
          salt: string;
        };
      };

      // TODO: this can be extracted into its own function
      // Derive key using Argon2id with stored parameters, assuming password "password"
      const password = 'password';
      const salt = sodium.from_base64(
        encJson.kdf.salt,
        sodium.base64_variants.ORIGINAL,
      );
      const key = sodium.crypto_pwhash(
        encJson.kdf.keyBytes,
        password,
        salt,
        encJson.kdf.opslimit,
        encJson.kdf.memlimit,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );

      // Decrypt private key from bundle (XChaCha20-Poly1305-ietf)
      const nonce = sodium.from_base64(
        encJson.cipher.nonce,
        sodium.base64_variants.ORIGINAL,
      );
      const ciphertext = sodium.from_base64(
        encJson.cipher.ciphertext,
        sodium.base64_variants.ORIGINAL,
      );
      const privateKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        null,
        nonce,
        key,
      );

      // Read and decrypt each entry (sealed box, base64 encoded)
      if (!fs.existsSync(entriesDir)) {
        console.error('No entries directory found at', entriesDir);
        return;
      }

      const files = (await readdir(entriesDir))
        .filter((f) => !f.startsWith('.'))
        .sort();

      for (const file of files) {
        const full = path.join(entriesDir, file);
        const contentB64 = (await readFile(full, 'utf-8')).trim();
        if (!contentB64) continue;
        try {
          const sealed = sodium.from_base64(
            contentB64,
            sodium.base64_variants.ORIGINAL,
          );
          const opened = sodium.crypto_box_seal_open(
            sealed,
            publicKey,
            privateKey,
          );
          const text = Buffer.from(opened).toString('utf-8');
          console.log(`[${file}] ${text}`);
        } catch (e) {
          console.error(`Failed to decrypt ${file}:`, e);
        }
      }
    } catch (error) {
      console.error('Failed to read entries:', error);
      process.exit(1);
    }
  });

program
  .command('new')
  .description('Create a new journal entry')
  .argument('<message>', 'Journal entry message')
  .action(async (message: string) => {
    try {
      const entriesDir = path.resolve(JOURNAL_DIR, 'entries');
      if (!fs.existsSync(entriesDir)) {
        fs.mkdirSync(entriesDir, { recursive: true });
      }

      // Use ISO timestamp, stripped for filename-friendly sorting
      const iso = new Date().toISOString(); // e.g. 2025-09-12T19:06:23.123Z
      const stamp = iso.replace(/[-:.]/g, ''); // 20250912T190623123Z
      const filename = `${stamp}.txt`;
      const filepath = path.join(entriesDir, filename);

      await writeFile(filepath, `${message}\n`);
      console.log('New entry saved to:', filepath);
    } catch (error) {
      console.error('Failed to write entry:', error);
      process.exit(1);
    }
  });

program.parse();
