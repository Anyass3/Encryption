/* eslint-disable @typescript-eslint/ban-ts-comment */
import NACL from 'tweetnacl';
import NACL_UTIL from 'tweetnacl-util';

// types
export type BoxKeyPair = {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
	privateKeyHex: string;
	publicKeyHex: string;
};

export type SignKeyPair = {
	signPublicKey: Uint8Array;
	signSecretKey: Uint8Array;
	signPublicKeyHex: string;
	signSecretKeyHex: string;
};
export type Encoding = 'hex' | 'base64';

const nacl = NACL as typeof NACL & { util: typeof NACL_UTIL };

nacl.util = NACL_UTIL;

export { nacl };

export const random = () => Math.floor(2147483648 * Math.random()).toString(36);

export const keyPair = <S extends boolean>(
	signature: S
): S extends true ? SignKeyPair : BoxKeyPair => {
	if (signature == true) {
		const k = nacl.sign.keyPair();
		// @ts-ignore
		return {
			signPublicKey: k.publicKey,
			signSecretKey: k.secretKey,
			signPublicKeyHex: bufferToHex(k.publicKey),
			signSecretKeyHex: bufferToHex(k.secretKey)
		};
	} else {
		const keys = nacl.box.keyPair();
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
			const ephemeralKeyPair = nacl.box.keyPair();

			// assemble encryption parameters - from string to UInt8
			let pubKeyUInt8Array;
			if (publicKey) {
				try {
					pubKeyUInt8Array = nacl.util.decodeBase64(publicKey);
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
			const msgParamsUInt8Array = nacl.util.decodeUTF8(msgParams.data);
			const nonce = nacl.randomBytes(nacl.box.nonceLength);
			// encrypt
			const encryptedMessage = nacl.box(
				msgParamsUInt8Array,
				nonce,
				pubKeyUInt8Array,
				ephemeralKeyPair.secretKey
			);
			// handle encrypted data
			const output = {
				version: 'x25519-xsalsa20-poly1305',
				nonce: nacl.util.encodeBase64(nonce),
				ephemPublicKey: nacl.util.encodeBase64(ephemeralKeyPair.publicKey),
				ciphertext: nacl.util.encodeBase64(encryptedMessage)
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
			const recieverEncryptionPrivateKey = nacl.box.keyPair.fromSecretKey(
				recieverPrivateKeyUint8Array
			).secretKey;
			// assemble decryption parameters
			const nonce = nacl.util.decodeBase64(encryptedData.nonce);
			const ciphertext = nacl.util.decodeBase64(encryptedData.ciphertext);
			const ephemPublicKey = nacl.util.decodeBase64(encryptedData.ephemPublicKey);
			// decrypt
			const decryptedMessage = nacl.box.open(
				ciphertext,
				nonce,
				ephemPublicKey,
				recieverEncryptionPrivateKey
			);
			// return decrypted msg data
			let output;
			try {
				output = nacl.util.encodeUTF8(decryptedMessage);
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
	try {
		const signature = nacl.sign(nacl.util.decodeUTF8(data), hexToBuffer(signSecretKey));
		return encoding == 'base64' ? nacl.util.encodeBase64(signature) : bufferToHex(signature);
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
		const data = nacl.sign.open(
			encoding == 'base64' ? nacl.util.decodeUTF8(signedData) : hexToBuffer(signedData),
			hexToBuffer(signPublicKey)
		);
		return nacl.util.encodeUTF8(data);
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
