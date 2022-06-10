
type StrArr = Array<string>;

interface Ethereum {
	chainId: string;
	enable: () => Promise<string[]>;
	isMetaMask: boolean;
	networkVersion: string;
	request: ({ method, params }: { method: string; params?: string[] }) => Promise<string>;
	selectedAddress: string;
}


type BoxKeyPair = {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
	privateKeyHex?: string;
	publicKeyHex?: string;
};

type SignKeyPair = {
	signPublicKey: Uint8Array;
	signSecretKey: Uint8Array;
	signPublicKeyHex?: string;
	signSecretKeyHex?: string;
};
type Encoding = 'hex' | 'base64';

declare let window: typeof globalThis & { ethereum: Ethereum };
