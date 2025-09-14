import { z } from 'zod';

// Load and validate encrypted private key bundle using Zod
export const EncBundleSchema = z.object({
  version: z.string(),
  cipher: z.object({
    alg: z.literal('xchacha20poly1305-ietf'),
    nonce: z.string(),
    ciphertext: z.string(),
  }),
  kdf: z.object({
    alg: z.literal('argon2id13'),
    keyBytes: z.number().int().positive(),
    opslimit: z.number().int().positive(),
    memlimit: z.number().int().positive(),
    salt: z.string(),
  }),
});

export type Entry = {
  filename: string;
  text: string;
  preview: string;
  date: Date;
};
