import { Command } from 'commander';
import fs from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import _sodium from 'libsodium-wrappers-sumo';
import { confirm, input } from '@inquirer/prompts';
import envPaths from 'env-paths';
import { deleteEntries, editEntry, getEntries, getPasswordWithRetry, init, selectEntries } from './utils';

const paths = envPaths('priv-journal');
const program = new Command();

program.name('priv-journal').description('A private journal CLI tool').version('0.1.0');

program
  .command('init')
  .description('Initialize a new keypair and setup encryption')
  .action(async () => {
    await init();
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
    const password = await getPasswordWithRetry();
    const entries = await getEntries(password);

    if (entries.length === 0) {
      console.error('No entries found.');
      return;
    }

    for (const entry of entries) {
      console.log(`[${entry.filename}] ${entry.text}`);
    }
  });

program
  .command('new')
  .description('Create a new journal entry')
  .argument('<message...>', 'Journal entry message')
  .action(async (originalMessage: string[]) => {
    const message = originalMessage.join(' ');

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

      // Join message parts and encrypt using sealed box and store as base64
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

program
  .command('edit')
  .description('Edit a journal entry')
  .action(async () => {
    const password = await getPasswordWithRetry();
    const entries = await getEntries(password);

    if (entries.length === 0) {
      console.error('No entries found.');
      return;
    }

    const selectedFilename = await selectEntries(entries);
    const selectedEntry = entries.find((e) => e.filename === selectedFilename);

    if (!selectedEntry) {
      console.error('Selected entry not found.');
      return;
    }

    const editedText = await input({
      message: 'Edit entry:',
      default: selectedEntry.text,
      prefill: 'editable',
    });

    await editEntry(selectedFilename as string, editedText);
  });

program
  .command('delete')
  .description('Delete journal entries')
  .action(async () => {
    const password = await getPasswordWithRetry();
    const entries = await getEntries(password);

    if (entries.length === 0) {
      console.error('No entries found.');
      return;
    }

    const selectedFilenames = await selectEntries(entries, { multiple: true });

    if (selectedFilenames.length === 0) {
      console.log('No entries selected for deletion.');
      return;
    }

    // Show preview of entries to be deleted
    console.log(`\nYou have selected ${selectedFilenames.length} entries to delete:`);
    for (const filename of selectedFilenames) {
      const entry = entries.find((e) => e.filename === filename);
      if (entry) {
        const preview = entry.text.length > 80 ? `${entry.text.substring(0, 80)}...` : entry.text;
        console.log(`- ${filename}: ${preview}`);
      }
    }

    const confirmed = await confirm({
      message: `Are you sure you want to permanently delete ${selectedFilenames.length} entries? This action cannot be undone.`,
      default: false,
    });

    if (!confirmed) {
      console.log('Deletion cancelled.');
      return;
    }

    const deletedCount = await deleteEntries(selectedFilenames);
    console.log(`Successfully deleted ${deletedCount} entries.`);
  });

program.parse();
