`inkcrypt` is an **encrypted-by-design** journal CLI. Its goal is to make it safe and effortless to write and revisit entries **without ever writing plaintext to disk**. Entries are encrypted client-side, in memory, before they're saved, and decrypted only locally when you view them.

When you write an entry, `inkcrypt` locks it before it ever touches your disk. It uses a "padlock" (your public key) to save only the locked version, so anyone opening the file just sees scrambled nonsense. When you want to read or edit, you unlock it with your password (your private key), make changes, and the moment you save it's locked again. Even your categories and tags live inside that lock, so the only thing visible on disk is a timestamped, gibberish-looking, file.

## Getting started

### Install (Global)

- Install from npm: `npm install -g inkcrypt`
- Verify: `inkcrypt --help`

### Use 

- Initialize encryption (first run): `inkcrypt init`
- Create a new entry: `inkcrypt new`
- Read entries: `inkcrypt read`
- Edit an entry: `inkcrypt edit`
- Delete entries: `inkcrypt delete`

### More features

- Create with category and tags
  - Category: pass an optional category as the first arg, e.g. `inkcrypt new @work`
  - Tags: include tags in your entry body like `#mood #goals`; tags are auto‑extracted

- Read by category
  - `inkcrypt read @work`
  - You can also filter by tags: `inkcrypt read @work --tags "#mood #goals"`

- Delete all (with optional filters)
  - Delete everything: `inkcrypt delete --all`
  - Delete by category: `inkcrypt delete --all @work`
  - With tags: `inkcrypt delete --all @work --tags "#mood #goals"`

- Change password
  - Re-encrypt all entries with a new password: `inkcrypt change-password`

## Some technical details

### Why `inkcrypt`?

Tools like `nb` and `jrnl` are excellent, and both support encryption, but you typically **opt in** per item or per journal. For example, `nb` creates password-protected notes when you pass `--encrypt`; it then prompts for the item's password and automatically re-encrypts after edits.

`jrnl` stores journals as plaintext unless you encrypt a journal (e.g., `jrnl --encrypt`). It also exposes an explicit `--decrypt` command that writes a plaintext journal back to disk if you choose.

`inkcrypt` takes a different stance: encryption is not a mode, **it's the default**. Writing uses your public key so you never need to unlock your private key to save new entries; reading requires your password. This removes the possibility of ever saving plaintext by mistake.

### Minimizing terminal traces

When editing an entry, `inkcrypt` opens the terminal's alternate screen buffer: it swaps to a separate screen while you edit, then restores your original terminal view when you exit, so your edited text is never saved in your terminal history. 

### How encryption works

`inkcrypt` uses `libsodium` **sealed box** construction to encrypt each entry with your public key. Sealed boxes are built on the `crypto_box` primitive (X25519 for key agreement + XSalsa20-Poly1305 for authenticated encryption), and they generate a one-time ephemeral keypair per message. The ciphertext includes the ephemeral public key; the nonce is derived with BLAKE2b from the ephemeral + recipient keys, so you don't need to manage nonces yourself. Only the holder of the corresponding private key can open the entry; tampering is detected by Poly1305.

Concretely, when you create a new entry, it calls `crypto_box_seal(message, publicKey)` and stores the result (Base64-encoded) on disk. When you read entries, `crypto_box_seal_open(ciphertext, publicKey, privateKey)` decrypts them locally.

**Metadata:** categories and tags are embedded inside the encrypted payload, so they're not visible on disk; the visible metadata is limited to filenames (timestamps) and file sizes.
