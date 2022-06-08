import * as openpgp from 'openpgp';
import * as bcrypt from 'bcrypt';
import * as keytar from 'keytar';
import fetch from 'electron-fetch';
import crypto from 'node:crypto';
const DHT = require('bittorrent-dht');
const dht = new DHT({
    verify: (signature: Buffer, message: Buffer, publicKey: Buffer) => {return true;}
});

const globalsalt: string = 'KI2opNu0OlTbORf6';
const serverurl: string = 'http://localhost:5000';

let publicKey: openpgp.PublicKey;
let privateKey: openpgp.PrivateKey;
let token: string;

function base64encode(str: string) {
    return Buffer.from(str, 'utf8').toString('base64');
}

function base64decode(base64str: string) {
    return Buffer.from(base64str, 'base64').toString('utf8');
}

function closeDHT() {
    dht.destroy();
}

async function sendRequest(command: string, body: any) {
    return await fetch(
        serverurl + '/' + command, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        }
    );
}

async function register(username: string, password: string) {
//  Generate key pair
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'rsa', // Type of the key
        rsaBits: 4096, // Curve, dht requires ed25519
        userIDs: [{ name: username, email: username + '@myoud.org' }], // you can pass multiple user IDs
        format: 'object' // output key format, defaults to 'armored'
    });

//  Prove ownership of public key by signing username + globalsalt
    const message = await openpgp.createMessage({text: username + globalsalt});
    const signature = await openpgp.sign({
        message,
        signingKeys: privateKey,
        detached: true
    });

//  Encryption key for the private key
    const salt2 = await bcrypt.genSalt();
    const encryptionKey = await bcrypt.hash(password, salt2);

    const privateKeyMessage = await openpgp.createMessage({
        text: privateKey.armor()
    });

//  Encrypt private key
    const encrypted_private_key = await openpgp.encrypt({
        message: privateKeyMessage,
        passwords: encryptionKey
    });

//  Hash password to prevent the server knowing it
    const hashed_password = await bcrypt.hash(password,
        await bcrypt.genSalt());

//  Push key to DHT
    const publicKeyBinary = publicKey.toPacketList().write();
    const value = Buffer.alloc(200).fill(username);
    const opts = {
        k: crypto.createHash('sha256').update(publicKeyBinary).digest(),
        sign: function(buf: Buffer) {
            return Buffer.from('no');
        },
        seq: 0,
        v: value
    };
    dht.put(opts);

//  Prepare to send the request
    const requestBody = {
        user_name: username,
        public_key: base64encode(publicKey.armor()),
        signature: base64encode(String(signature)),
        encrypted_private_key: base64encode(String(encrypted_private_key)),
        hashed_password,
        salt2
    };

//  Send the request
    const registerResponse = sendRequest('register', requestBody);

    return registerResponse;
}

async function login(username: string, password: string, rememberMe: boolean) {
//  Request the salt to hash the password
    const requestBody = {
        user_name: username
    };

    const response = await sendRequest('get_salt', requestBody);
    const { salt } = JSON.parse(await response.text());

//  Hash the password
    const hashed_password = await bcrypt.hash(password, salt);

//  Send login request
    const loginRequest = {
        user_name: username,
        hashed_password,
        session_timeout: rememberMe ? 0 : 900
    }

//  Extract values out of response
    const params = JSON.parse(await (await sendRequest('login', loginRequest)).text());
    token = params.token;
    const encrypted_private_key = await openpgp.readMessage({
        armoredMessage: base64decode(params.sk)
    });

//  Get salt2 to decrypt private key
    const response2 = await sendRequest('get_salt2', requestBody);
    const { salt2 } = JSON.parse(await response2.text());

//  Symmetric decryption key
    const decKey = await bcrypt.hash(password, salt2);

//  Decrypt private key
    const decryptedKey = await openpgp.decrypt({
        message: encrypted_private_key,
        passwords: decKey
    });

//  Read private key
    privateKey = await openpgp.readPrivateKey({
        armoredKey: decryptedKey.data.toString()
    });

    publicKey = privateKey.toPublic();

//  Save all of the credentials if "remember me" was ticked
    if (rememberMe) {
        keytar.setPassword('publicKey', username, publicKey.armor());
        keytar.setPassword('privateKey', username, privateKey.armor());
        keytar.setPassword('token', username, token);
    }
}

async function logout() {

}

const api = {
    register,
    login,
    logout,
    closeDHT
};

export {api as default};
