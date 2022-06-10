import NACL from 'tweetnacl';
import NUtils from 'tweetnacl-util';
export type BoxKeyPair = {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
	privateKeyHex?: string;
	publicKeyHex?: string;
};
export type SignKeyPair = {
	signPublicKey: Uint8Array;
	signSecretKey: Uint8Array;
	signPublicKeyHex?: string;
	signSecretKeyHex?: string;
};
export type Encoding = 'hex' | 'base64';
export const nacl: NACL & {
	util: typeof NUtils;
};
export const keyPair: <S extends boolean>(
	signature: S
) => S extends true ? SignKeyPair : BoxKeyPair;
export const sign: (data: string, signSecretKey: string, encoding?: Encoding) => string;
export const verifySignature: (
	signedData: string,
	signPublicKey: string,
	encoding?: Encoding
) => string;
export const verifySignatures: (
	signedData: string,
	signPublicKeys: string[],
	encoding?: Encoding
) => string;
export const signMultiple: (data: string, signSecretKeys: string[], encoding?: Encoding) => string;
export function bufferToHex(buffer: Uint8Array): string;
export function hexToBuffer(hex: string): Uint8Array;
export function random(): string;
export const encrypt: (message?: string, publicKeyHex?: string) => Promise<string>;
export const decrypt: (hexData: string, privateKey: string) => Promise<string>;
