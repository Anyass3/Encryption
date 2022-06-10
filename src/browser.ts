import { bufferToHex, hexToBuffer, nacl, _decrypt, _encrypt } from './lib';

export * from './lib';

// types
interface Ethereum {
	chainId: string;
	enable: () => Promise<string[]>;
	isMetaMask: boolean;
	networkVersion: string;
	request: ({ method, params }: { method: string; params?: string[] }) => Promise<string>;
	selectedAddress: string;
}

declare let window: typeof globalThis & { ethereum: Ethereum };

export const getMMPublicKey = async () => {
	if (!(await startMetamask())) return;
	try {
		const pkey = await window.ethereum.request({
			method: 'eth_getEncryptionPublicKey',
			params: [window.ethereum.selectedAddress]
		});
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
		return;
	}
	const encrypted = _encrypt(
		{ publicKey, publicKeyHex },
		{ data: message },
		'x25519-xsalsa20-poly1305'
	);
	const buffer = nacl.util.decodeUTF8(JSON.stringify(encrypted));
	const hex = bufferToHex(buffer);
	return hex;
};

export const decrypt = async (hexData: string, privateKey?: string) => {
	const buffer = hexToBuffer(hexData);
	const encryptedData = JSON.parse(nacl.util.encodeUTF8(buffer));
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
	return decryptedData;
};
