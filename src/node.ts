import { bufferToHex, hexToBuffer, nacl, _decrypt, _encrypt } from './lib';

export * from './lib';

export const encrypt = async (message = 'message', publicKeyHex?: string) => {
	const encrypted = _encrypt(
		{ publicKey: undefined, publicKeyHex },
		{ data: message },
		'x25519-xsalsa20-poly1305'
	);
	const buffer = nacl.util.decodeUTF8(JSON.stringify(encrypted));
	const hex = bufferToHex(buffer);
	return hex;
};

export const decrypt = async (hexData: string, privateKey: string) => {
	const buffer = hexToBuffer(hexData);
	const encryptedData = JSON.parse(nacl.util.encodeUTF8(buffer));
	let decryptedData;
	try {
		decryptedData = _decrypt(encryptedData, privateKey);
	} catch (error) {
		console.error(error);
	}
	return decryptedData;
};
