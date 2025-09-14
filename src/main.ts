import { Command } from 'commander';
import fs from 'fs';
import { writeFile, readFile, readdir } from 'fs/promises';
import path from 'path';
import _sodium from 'libsodium-wrappers-sumo';
import { password as promptPassword } from '@inquirer/prompts';
import envPaths from 'env-paths';
import { getKeys, init } from "./utils";
import { z } from 'zod';
import { EncBundleSchema } from "./schemas";

const paths = envPaths('priv-journal');
const program = new Command();

program
  .name('priv-journal')
  .description('A private journal CLI tool')
  .version('0.1.0');

program
  .command('init')
  .description('Initialize a new keypair and setup encryption')
  .action(async () => { await init() });

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


      const entriesDir = path.resolve(paths.data);

      // TODO: this can be extracted into its own function
      // Derive key using Argon2id with stored parameters
      const password = await promptPassword({
        message: 'Enter your password',
        mask: true,
      });

      const { publicKey, privateKey } = await getKeys(password);

      // Read and decrypt each entry (sealed box, base64 encoded)
      if (!fs.existsSync(entriesDir)) {
        console.error('No entries found; data folder missing at', entriesDir);
        return;
      }

      const files = (await readdir(entriesDir))
        .filter((f) => !f.startsWith('.'))
        .sort();

      for (const file of files) {
        const full = path.join(entriesDir, file);
        const contentB64 = (await readFile(full, 'utf-8')).trim();
        if (!contentB64) continue;
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
      }
    } catch (error) {
      console.error('Incorrect password. Please try again.');
      console.error(error)
      process.exit(1);
    }
  });

program
  .command('new')
  .description('Create a new journal entry')
  .argument('<message>', 'Journal entry message')
  .action(async (message: string) => {
    try {
      await _sodium.ready;
      const sodium = _sodium;

      const pubKeyPath = path.resolve(paths.config, 'pubkey.bin');
      const entriesDir = path.resolve(paths.data);
      if (!fs.existsSync(entriesDir)) {
        fs.mkdirSync(entriesDir, { recursive: true });
      }
      if (!fs.existsSync(pubKeyPath)) {
        throw new Error(`Missing public key at ${pubKeyPath}. Run 'init' first.`);
      }

      // Load public key (raw bytes)
      const publicKey = new Uint8Array(await readFile(pubKeyPath));

      // Use ISO timestamp, stripped for filename-friendly sorting
      const iso = new Date().toISOString(); // e.g. 2025-09-14T19:06:23.123Z
      const stamp = iso.replace(/[-:.]/g, ''); // 20250914T190623123Z
      const filename = `${stamp}.txt`;
      const filepath = path.join(entriesDir, filename);

      // Encrypt message using sealed box and store as base64
      const messageBytes = new TextEncoder().encode(message);
      const sealed = sodium.crypto_box_seal(messageBytes, publicKey);
      const sealedB64 = sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL);

      await writeFile(filepath, `${sealedB64}\n`);
      console.log('New encrypted entry saved to:', filepath);
    } catch (error) {
      console.error('Failed to write entry:', error);
      process.exit(1);
    }
  });

program.parse();
