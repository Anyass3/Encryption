/* eslint-disable @typescript-eslint/ban-ts-comment */
import NACL from 'tweetnacl';
import NUtils from 'tweetnacl-util';

// types
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

const N = NACL as typeof NACL & { util: typeof NUtils };

N.util = NUtils;

export { N };

export const random = () => Math.floor(2147483648 * Math.random()).toString(36);

export const keyPair = <S extends boolean>(
	signature: S
): S extends true ? SignKeyPair : BoxKeyPair => {
	if (signature == true) {
		const k = N.sign.keyPair();
		// @ts-ignore
		return {
			signPublicKey: k.publicKey,
			signSecretKey: k.secretKey,
			signPublicKeyHex: bufferToHex(k.publicKey),
			signSecretKeyHex: bufferToHex(k.secretKey)
		};
	} else {
		const keys = N.box.keyPair();
		const publicKeyHex = bufferToHex(keys.publicKey);
		const privateKeyHex = bufferToHex(keys.secretKey);

		//@ts-ignore
		return { privateKey: keys.secretKey, publicKey: keys.publicKey, privateKeyHex, publicKeyHex };
	}
};
export function _encrypt({ publicKeyHex, publicKey }, msgParams, version) {
	switch (version) {
		case 'x25519-xsalsa20-poly1305': {
			if (typeof msgParams.data !== 'string') {
				throw new Error(
					'Cannot detect secret message, message params should be of the form {data: "secret message"} '
				);
			}
			// generate ephemeral keypair
			const ephemeralKeyPair = N.box.keyPair();

			// assemble encryption parameters - from string to UInt8
			let pubKeyUInt8Array;
			if (publicKey) {
				try {
					pubKeyUInt8Array = N.util.decodeBase64(publicKey);
				} catch (err) {
					throw new Error('Bad public key');
				}
			} else if (publicKeyHex) {
				try {
					pubKeyUInt8Array = hexToBuffer(publicKeyHex);
				} catch (err) {
					throw new Error('Bad public key');
				}
			} else {
				throw new Error('No public key');
			}
			const msgParamsUInt8Array = N.util.decodeUTF8(msgParams.data);
			const nonce = N.randomBytes(N.box.nonceLength);
			// encrypt
			const encryptedMessage = N.box(
				msgParamsUInt8Array,
				nonce,
				pubKeyUInt8Array,
				ephemeralKeyPair.secretKey
			);
			// handle encrypted data
			const output = {
				version: 'x25519-xsalsa20-poly1305',
				nonce: N.util.encodeBase64(nonce),
				ephemPublicKey: N.util.encodeBase64(ephemeralKeyPair.publicKey),
				ciphertext: N.util.encodeBase64(encryptedMessage)
			};
			// return encrypted msg data
			return output;
		}
		default:
			throw new Error('Encryption type/version not supported');
	}
}
export function _decrypt(encryptedData, receiverPrivateKey) {
	switch (encryptedData.version) {
		case 'x25519-xsalsa20-poly1305': {
			// string to buffer to UInt8Array
			const recieverPrivateKeyUint8Array = hexToBuffer(receiverPrivateKey);
			const recieverEncryptionPrivateKey = N.box.keyPair.fromSecretKey(
				recieverPrivateKeyUint8Array
			).secretKey;
			// assemble decryption parameters
			const nonce = N.util.decodeBase64(encryptedData.nonce);
			const ciphertext = N.util.decodeBase64(encryptedData.ciphertext);
			const ephemPublicKey = N.util.decodeBase64(encryptedData.ephemPublicKey);
			// decrypt
			const decryptedMessage = N.box.open(
				ciphertext,
				nonce,
				ephemPublicKey,
				recieverEncryptionPrivateKey
			);
			// return decrypted msg data
			let output;
			try {
				output = N.util.encodeUTF8(decryptedMessage);
			} catch (err) {
				throw new Error('Decryption failed.');
			}
			if (output) {
				return output;
			}
			throw new Error('Decryption failed.');
		}
		default:
			throw new Error('Encryption type/version not supported.');
	}
}

export const sign = (data: string, signSecretKey: string, encoding: Encoding = 'hex') => {
	console.log('sign', { data, signSecretKey });
	try {
		const signature = N.sign(N.util.decodeUTF8(data), hexToBuffer(signSecretKey));
		return encoding == 'base64' ? N.util.encodeBase64(signature) : bufferToHex(signature);
	} catch (error) {
		console.error(error.message);
	}
};
export const verifySignature = (
	signedData: string,
	signPublicKey: string,
	encoding: Encoding = 'hex'
) => {
	try {
		const data = N.sign.open(
			encoding == 'base64' ? N.util.decodeUTF8(signedData) : hexToBuffer(signedData),
			hexToBuffer(signPublicKey)
		);
		console.log('verifySignature', { signedData, signPublicKey, data });
		return N.util.encodeUTF8(data);
	} catch (error) {
		console.error(error.message);
	}
};

export const verifySignatures = (
	signedData: string,
	signPublicKeys: string[],
	encoding?: Encoding
) => {
	return signPublicKeys.reduce((signedData, signPublicKey) => {
		return verifySignature(signedData, signPublicKey, encoding);
	}, signedData);
};

export const signMultiple = (data: string, signSecretKeys: string[], encoding?: Encoding) => {
	return signSecretKeys.reduce((data, signSecretKeys) => {
		return sign(data, signSecretKeys, encoding);
	}, data);
};

export function bufferToHex(buffer) {
	return Array.from(new Uint8Array(buffer))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export function hexToBuffer(hex) {
	const tokens = hex.match(/.{1,2}(?=(.{2})+(?!.))|.{1,2}$/g);
	return new Uint8Array(tokens.map((token) => parseInt(token, 16)));
}
