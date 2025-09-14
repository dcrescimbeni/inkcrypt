import _sodium from 'libsodium-wrappers-sumo';
import { writeFile, readFile } from 'fs/promises';
import { password as promptPassword } from '@inquirer/prompts';
import fs from 'fs';
import envPaths from 'env-paths';
import path from 'path';
import { EncBundleSchema } from "./schemas";

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

    console.info("Store your password somewhere safe. You'll need it to decrypt your journal. If you lose it, nobody can help you recover it.");

    const password = await promptPassword({
      message: 'Set an encryption password',
      mask: true,
      validate: (input) =>
        input && input.length >= 8 ? true : 'Use at least 8 characters',
    });
    const passwordConfirmation = await promptPassword({
      message: 'Confirm your encryption password',
      mask: true,
      validate: (input) =>
        input && input.length >= 8 ? true : 'Use at least 8 characters',
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

    return { pubKeyPath, privEncPath, configPath };
  } catch (error) {
    console.error('Error during initialization:', error);
    process.exit(1);
  }
}

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

  const encJson = EncBundleSchema.parse(
    JSON.parse(await readFile(privEncPath, 'utf-8')),
  );

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

  return { publicKey, privateKey };
}