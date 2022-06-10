import { bufferToHex, hexToBuffer, N, _decrypt, _encrypt } from './lib';

export * from './lib'

export const getMMPublicKey = async () => {
	if (!(await startMetamask())) return;
	try {
		const pkey = await window.ethereum.request({
			method: 'eth_getEncryptionPublicKey',
			params: [window.ethereum.selectedAddress]
		});
		console.log('eth_getEncryptionPublicKey', pkey);
		return pkey;
	} catch (error) {
		console.error(error);
	}
};

export const isMetaMask = typeof window != 'undefined' ? window.ethereum?.isMetaMask : false;

const startMetamask = async () => {
	if (!isMetaMask) return;
	try {
		return await window.ethereum.request({ method: 'eth_requestAccounts' });
	} catch (error) {
		console.error(error);
	}
};


export const encrypt = async (message = 'message', publicKeyHex?: string) => {
	let publicKey;
	if (!publicKeyHex) publicKey = await getMMPublicKey();
	if (!publicKey && !publicKeyHex) {
		console.error('NO Public Key');
		return;
	}
	const encrypted = _encrypt(
		{ publicKey, publicKeyHex },
		{ data: message },
		'x25519-xsalsa20-poly1305'
	);
	const buffer = N.util.decodeUTF8(JSON.stringify(encrypted));
	const hex = bufferToHex(buffer);
	console.log({ encrypted, hex, buffer });
	window['decrypt'] = decrypt;
	return hex;
};

export const decrypt = async (hexData: string, privateKey?: string) => {
	const buffer = hexToBuffer(hexData);
	const encryptedData = JSON.parse(N.util.encodeUTF8(buffer));
	let decryptedData;
	try {
		if (privateKey) decryptedData = _decrypt(encryptedData, privateKey);
		else {
			await startMetamask();
			decryptedData = await window.ethereum.request({
				method: 'eth_decrypt',
				params: ['0x' + hexData, window.ethereum.selectedAddress]
			});
		}
	} catch (error) {
		console.error(error);
	}
	console.log({ encryptedData, buffer, decryptedData });
	return decryptedData;
};