import fs from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { confirm, input } from '@inquirer/prompts';
import { Command } from 'commander';
import envPaths from 'env-paths';
import _sodium from 'libsodium-wrappers-sumo';
import {
  deleteEntries,
  editEntry,
  extractCategoryFromArgs,
  extractTagsFromText,
  formatEntryWithMetadata,
  getEntries,
  getEntryCount,
  getPasswordWithRetry,
  init,
  parseMetadata,
  selectEntries,
} from './utils';

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
  .argument('[category]', 'Filter entries by category (e.g., @work)')
  .option('-t, --tags <tags>', 'Filter by tags (e.g., mood, #goals)')
  .action(async (category?: string, options?: { tags?: string }) => {
    const password = await getPasswordWithRetry();

    // Parse tags from options
    const tags = options?.tags ? options.tags.split(/\s+/).filter(Boolean) : undefined;

    const entries = await getEntries({ password, category, tags });

    if (entries.length === 0) {
      return;
    }

    for (const entry of entries) {
      let displayText = `[${entry.filename}]`;

      // Add metadata display
      if (entry.metadata?.category || entry.metadata?.tags) {
        const metadataParts = [];
        if (entry.metadata.category) {
          metadataParts.push(entry.metadata.category);
        }
        if (entry.metadata.tags && entry.metadata.tags.length > 0) {
          metadataParts.push(entry.metadata.tags.join(' '));
        }
        displayText += ` ${metadataParts.join(' ')}`;
      }

      // Parse content to show only the actual content (without metadata header)
      const { content } = parseMetadata(entry.text);
      displayText += ` - ${content}`;

      console.log(displayText);
    }
  });

program
  .command('new')
  .description('Create a new journal entry')
  .argument('<message...>', 'Journal entry message')
  .action(async (originalMessage: string[]) => {
    // Extract category from arguments
    const { category, remainingArgs } = extractCategoryFromArgs(originalMessage);
    const message = remainingArgs.join(' ');

    // Extract tags from the message content
    const tags = extractTagsFromText(message);

    // Create metadata object
    const metadata = {
      ...(category && { category }),
      ...(tags.length > 0 && { tags }),
    };

    // Format the entry with metadata
    const entryText = formatEntryWithMetadata(message, metadata);

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

      // Encrypt the formatted entry with metadata
      const messageBytes = new TextEncoder().encode(entryText);
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
  .argument('[category]', 'Filter entries by category (e.g., @work)')
  .option('-t, --tags <tags>', 'Filter by tags (e.g., mood, #goals)')
  .action(async (category?: string, options?: { tags?: string }) => {
    const password = await getPasswordWithRetry();

    // Parse tags from options
    const tags = options?.tags ? options.tags.split(/\s+/).filter(Boolean) : undefined;

    const entries = await getEntries({ password, category, tags });

    if (entries.length === 0) {
      return;
    }

    const selectedFilename = await selectEntries(entries);
    const selectedEntry = entries.find((e) => e.filename === selectedFilename);

    if (!selectedEntry) {
      console.error('Selected entry not found.');
      return;
    }

    // Parse the existing entry to extract metadata and content
    const { metadata: existingMetadata, content: existingContent } = parseMetadata(selectedEntry.text);

    const editedText = await input({
      message: 'Edit entry:',
      default: existingContent,
      prefill: 'editable',
    });

    // Extract tags from the edited content
    const newTags = extractTagsFromText(editedText);

    // Preserve category, update tags
    const updatedMetadata = {
      ...(existingMetadata.category && { category: existingMetadata.category }),
      ...(newTags.length > 0 && { tags: newTags }),
    };

    // Format the entry with updated metadata
    const formattedEntry = formatEntryWithMetadata(editedText, updatedMetadata);

    await editEntry(selectedFilename as string, formattedEntry);
  });

program
  .command('delete')
  .description('Delete journal entries')
  .argument('[category]', 'Filter entries by category (e.g., @work)')
  .option('-t, --tags <tags>', 'Filter by tags (e.g., mood, #goals)')
  .action(async (category?: string, options?: { tags?: string }) => {
    const password = await getPasswordWithRetry();

    // Parse tags from options
    const tags = options?.tags ? options.tags.split(/\s+/).filter(Boolean) : undefined;

    const entries = await getEntries({ password, category, tags });

    if (entries.length === 0) {
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

program
  .command('deleteAll')
  .description('Delete all journal entries')
  .argument('[category]', 'Filter entries by category (e.g., @work)')
  .option('-t, --tags <tags>', 'Filter by tags (e.g., mood, #goals)')
  .action(async (category?: string, options?: { tags?: string }) => {
    // Parse tags from options
    const tags = options?.tags ? options.tags.split(/\s+/).filter(Boolean) : undefined;

    // Get password first if category or tag filtering is needed
    let password: string | undefined;
    if (category || (tags && tags.length > 0)) {
      password = await getPasswordWithRetry();
    }

    const entryCount = await getEntryCount({ password, category, tags });

    if (entryCount === 0) {
      return;
    }

    const filters = [];
    if (category) filters.push(`category ${category}`);
    if (tags && tags.length > 0) filters.push(`tags ${tags.join(', ')}`);

    if (filters.length > 0) {
      console.log(`You have ${entryCount} entries matching ${filters.join(' and ')} that will be permanently deleted.`);
    } else {
      console.log(`You have ${entryCount} entries that will be permanently deleted.`);
    }

    const filterDescription = filters.length > 0 ? ` matching ${filters.join(' and ')}` : '';
    const message = `Are you sure you want to permanently delete all ${entryCount} entries${filterDescription}? This action cannot be undone.`;

    const confirmed = await confirm({
      message,
      default: false,
    });

    if (!confirmed) {
      console.log('Deletion cancelled.');
      return;
    }

    if (!password) {
      password = await getPasswordWithRetry();
    }

    const entries = await getEntries({ password, category, tags });
    const filenames = entries.map((e) => e.filename);

    const deletedCount = await deleteEntries(filenames);
    console.log(`Successfully deleted ${deletedCount} entries.`);
  });

program.parse();
