# Encryption

Public and private encryption and signatures with meta-mask support

> It can be used both in nodejs and browser

# API

#### Few important types

```typescript
interface BoxKeyPair {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
	privateKeyHex?: string;
	publicKeyHex?: string;
}
interface SignKeyPair {
	signPublicKey: Uint8Array;
	signSecretKey: Uint8Array;
	signPublicKeyHex?: string;
	signSecretKeyHex?: string;
}
const Encoding: 'hex' | 'base64';
```

#### Both nodejs and browser client

- nacl

  ```typescript
  const nacl: NACL & { util: NACL_UTIL };
  ```

  NACL --> tweetnacl
  
  NACL_UTIL --> tweetnacl-util

- keyPair

  A function that generates a random signature keypair if `keyPair(true)` else encryption keypair

  ```typescript
  const keyPair: <S extends boolean>(signature: S) => S extends true ? SignKeyPair : BoxKeyPair;
  ```

- sign

  Signs a string data with a secret key in `hex` string and returns a signed data in your prefered string encoding

  ```typescript
  const sign: (data: string, signSecretKey: string, encoding?: Encoding) => string;
  ```

- verifySignature

  Verifies a signed string data depending on the encoding(`hex`or`base64`)
  
  `signPublicKey` is `hex` string.

  ```typescript
  const verifySignature: (signedData: string, signPublicKey: string, encoding?: Encoding) => string;
  ```

- signMultiple

  Similar to `sign` but signs a string data with multiple secret keys
  
  The order is important for verification.

  ```typescript
  const signMultiple: (data: string, signSecretKeys: string[], encoding?: Encoding) => string;
  ```

- verifySignatures

  Similar to `verifySignature` but verifies a string data with multiple public keys
  
  The order should be the reverse of the secret keys during signing.

  ```typescript
  const verifySignatures: (signedData: string, signPublicKeys: string[], encoding?: Encoding) => string;
  ```

- bufferToHex

  Converts a NodeJS Buffer or browser client Uint8Array to hex string

  ```typescript
  function bufferToHex(buffer: Buffer | Uint8Array): string;
  ```

- hexToBuffer

  Converts a hex string to NodeJS Buffer or browser client Uint8Array

  ```typescript
  function hexToBuffer(hex: string): Buffer | Uint8Array;
  ```

- random

  Generates a random short string

  ```typescript
  function random(): string;
  ```

- encrypt

  Encrypts a string data; publicKey is a hex string

  It returns the an encrypted hex string

  ```typescript
  const encrypt: (data: string, publicKey: string) => Promise<string>;
  ```

  In browser client the publicKey is optional. If publicKey is undefined, it assumes you want use your MetaMask account for ecryption. That is using your selected MetaMask account publicKey.

- decrypt

  Decrypts a hex string data; privateKey is a hex string

  It returns the original string that was encrypted

  ```typescript
  const decrypt: (encryptedData: string, privateKey: string) => Promise<string>;
  ```

  In browser client the privateKey is optional. If privateKey is undefined, it assumes you want use your MetaMask account for decryption

#### Only in browser client

- getMetaMaskPublicKey

  Gets the MetaMask public key of a selected account and returns it as Base64

  ```typescript
  const getMetaMaskPublicKey: () => Promise<string>;
  ```

- isMetaMask

  True if MetaMask is available else False

  ```typescript
  const isMetaMask: boolean;
  ```
