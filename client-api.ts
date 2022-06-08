import * as openpgp from 'openpgp';
import * as bcrypt from 'bcrypt';
import * as keytar from 'keytar';
import * as stream from '@openpgp/web-stream-tools';
import fetch from 'electron-fetch';
import crypto from 'node:crypto';
import fs from 'node:fs';
const DHT = require('bittorrent-dht');
const dht = new DHT({
    verify: (signature: Buffer, message: Buffer, publicKey: Buffer) => {return true;}
});

const globalsalt: string = 'KI2opNu0OlTbORf6';
const serverurl: string = 'http://localhost:5000';

let publicKey: openpgp.PublicKey;
let privateKey: openpgp.PrivateKey;
let token: string;
let uname: string;

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
    uname = username;

//  Save all of the credentials if "remember me" was ticked
    if (rememberMe) {
        keytar.setPassword('privateKey', username, privateKey.armor());
        keytar.setPassword('token', username, token);
    }
}

async function logout() {
//  Delete from keytar
    keytar.deletePassword('privateKey', uname);
    keytar.deletePassword('token', uname);

//  Send logout request to server
    const body = {
        token
    };

//  Destruct / Clear fields in memory
    privateKey = new Object() as openpgp.PrivateKey;
    publicKey = privateKey;
    token = '';
    uname = '';

    return await sendRequest('logout', body);
}

async function restoreSession() {
    try {
        uname = (await keytar.findCredentials('privateKey'))[0].account;
    } catch {
        return false;
    }
    const armoredKey = (await keytar.findCredentials('privateKey'))[0].password;
    token = (await keytar.findCredentials('token'))[0].password;

    privateKey = await openpgp.readPrivateKey({
        armoredKey: armoredKey
    });
    publicKey = privateKey.toPublic();

    return true;
}

async function downloadFile(remotePath: string, localPath: string) {
//  Get stream token from server
    const body = {
        token,
        path: remotePath
    };
    const params = JSON.parse(await (await sendRequest('download_file', body)).text());

//  Extract information from server response
    const stream_token: string = params.token;
    const key = base64decode(params.key);
    const filesig = base64decode(params.filesig);

    const keyMessage = await openpgp.readMessage({
        binaryMessage: new Uint8Array(Buffer.from(key))
    });

    const decryptedKey = await openpgp.decrypt({
        message: keyMessage,
        decryptionKeys: privateKey
    });

    const response = await fetch(serverurl + '/download_stream/' + stream_token);
    const buffer = new Uint8Array(await response.arrayBuffer());

    const encrypted = await openpgp.readMessage({
        binaryMessage: buffer
    });

    const decrypted = await openpgp.decrypt({
        message: encrypted,
        passwords: decryptedKey.data.toString(),
        format: 'binary'
    });

    const fileMessage = await openpgp.readMessage({
        binaryMessage: decrypted.data
    });

    const signature = await openpgp.readSignature({
        binarySignature: new Uint8Array(Buffer.from(filesig))
    });

    const ver = await openpgp.verify({
        message: fileMessage,
        signature,
        verificationKeys: publicKey
    });

    if (!await ver.signatures[0].verified) {
        throw new Error('File signature invalid');
    }

    const buf = decrypted.data;

    fs.writeFile(localPath, buf, (err) => {
        if (err) throw err;
    });
}

async function uploadFile(remotePath: string, localPath: string) {
//  Generate symmetric key to encrypt the file with
    const key = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        key[i] = Math.floor(Math.random() * 256);
    }

//  Create OpenPGP message
    const keyMessage = await openpgp.createMessage({
        binary: key
    });

//  Encrypt encryption key using public key
    const encrypted = await openpgp.encrypt({
        message: keyMessage,
        encryptionKeys: publicKey,
        format: 'binary'
    });

//  Path message
    const pathMessage = await openpgp.createMessage({
        text: remotePath
    });

//  Path signature
    const signature = await openpgp.sign({
        message: pathMessage,
        signingKeys: privateKey,
        detached: true,
        format: 'binary'
    });

//  Read file
    const buffer = new Uint8Array(fs.readFileSync(localPath));

//  File message
    const fileMessage = await openpgp.createMessage({
        binary: buffer
    });

//  File signature
    const fileSignature = await openpgp.sign({
        message: fileMessage,
        signingKeys: privateKey,
        format: 'binary'
    });

//  Get stream token from server
    const body = {
        token,
        path: remotePath,
        file_key: base64encode(encrypted.toString()),
        pathsig: base64encode(signature.toString()),
        filesig: base64encode(fileSignature.toString())
    };

    const encryptedFile = await openpgp.encrypt({
        message: fileMessage,
        format: 'binary'
    })

    const stream_token = JSON.parse(await (await sendRequest('upload_file', body)).text()).token;

    return await sendRequest('upload_stream/' + stream_token, encryptedFile);
}

const api = {
    register,
    login,
    logout,
    restoreSession,
    downloadFile,
    uploadFile,
    closeDHT
};

export {api as default};
