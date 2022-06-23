import * as openpgp from 'openpgp';
import * as bcrypt from 'bcrypt';
import * as keytar from 'keytar';
import * as stream from '@openpgp/web-stream-tools';
import * as utilbytes from 'uint8arrays';
import strftime from 'strftime';
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

let cachedFiles = new Map<string, {
    date: number,
    key: Uint8Array,
    isFolder: boolean
}>();

let sharedCachedFiles = new Map<string, {
    date: number,
    key: Uint8Array,
    isFolder: boolean,
    username: string
}>();

function base64encode(str: string) {
    return Buffer.from(str, 'utf8').toString('base64');
}

function base64decode(base64str: string) {
    return Buffer.from(base64str, 'base64').toString('utf8');
}

function closeDHT() {
    dht.destroy();
}

function generateKey() {
    const key = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        key[i] = Math.floor(Math.random() * 256);
    }

    return key;
}

function bufferToString(buf: Uint8Array) {
    return utilbytes.toString(buf, 'ascii');
}

function stringToBuffer(str: string) {
    return utilbytes.fromString(str, 'ascii');
}

async function encryptBuffer(buf: Uint8Array, key: Uint8Array | string) {
    const message = await openpgp.createMessage({
        binary: buf,
        format: 'binary'
    });

    const password = key instanceof Uint8Array ? bufferToString(key) : key;

    const encrypted = await openpgp.encrypt({
        message,
        passwords: password,
        format: 'binary'
    });

    return encrypted;
}

async function decryptBuffer(buf: Uint8Array, key: Uint8Array | string) {
    const password = key instanceof Uint8Array ? bufferToString(key) : key;

    const decrypted = await openpgp.decrypt({
        message: await openpgp.createMessage({
            binary: buf,
            format: 'binary'
        }),
        passwords: password,
        format: 'binary'
    });

    return decrypted.data;
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
        type: 'ecc', // Type of the key
        curve: 'ed25519', // Curve, dht requires ed25519
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
        signature: base64encode(signature),
        encrypted_private_key: base64encode(encrypted_private_key),
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
        armoredKey: decryptedKey.data
    });

    publicKey = privateKey.toPublic();
    uname = username;

//  Save all of the credentials if "remember me" was ticked
    if (rememberMe) {
        await keytar.setPassword('privateKey', username, bufferToString(privateKey.toPacketList().write()));
        await keytar.setPassword('token', username, token);
    }
}

async function logout() {
//  Delete from keytar
    await keytar.deletePassword('privateKey', uname);
    await keytar.deletePassword('token', uname);

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
//  Get accounts from keytar
    const privateKeys = await keytar.findCredentials('privateKey');
    if (privateKeys.length === 0) {
        return false;
    }
    uname = privateKeys[0].account;
    const binaryKey = stringToBuffer(privateKeys[0].password);
    token = (await keytar.findCredentials('token'))[0].password;

    privateKey = await openpgp.readPrivateKey({
        binaryKey
    });
    publicKey = privateKey.toPublic();

    return true;
}

async function listSavedAccounts() {
    const privateKeys = await keytar.findCredentials('privateKey');
    return privateKeys.map(key => key.account);
}

async function restoreUserSession(username: string) {
    const privateKeys = await keytar.findCredentials('privateKey');
    for (let i = 0; i < privateKeys.length; i++) {
        if (privateKeys[i].account === username) {
            uname = username;
            const binaryKey = stringToBuffer(privateKeys[i].password);
            token = (await keytar.findCredentials('token'))[i].password;

            privateKey = await openpgp.readPrivateKey({
                binaryKey
            });
            publicKey = privateKey.toPublic();

            return;
        }
    }

    throw new Error('User not saved');
}

async function uploadFile(remotePath: string, localPath: string) {
//  Generate symmetric key to encrypt the file with
    const key = generateKey();

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
    const buffer = fs.readFileSync(localPath);

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

    const encryptedFile = await openpgp.encrypt({
        message: fileMessage,
        passwords: bufferToString(key),
        format: 'binary'
    });

//  Get stream token from server
    const body = {
        token,
        path: remotePath,
        file_key: base64encode(bufferToString(encrypted)),
        pathsig: base64encode(bufferToString(signature)),
        filesig: base64encode(bufferToString(fileSignature))
    };

    const stream_token = JSON.parse(await (await sendRequest('upload_file', body)).text()).token;

//  TODO: convert to https and change url to serverurl
    return await fetch(serverurl + '/upload_stream/' + stream_token, {
        method: 'POST',
        body: bufferToString(encryptedFile)
    });
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
//  const filesig = base64decode(params.filesig);

    const keyMessage = await openpgp.readMessage({
        binaryMessage: stringToBuffer(key)
    });

    const decryptedKey = await openpgp.decrypt({
        message: keyMessage,
        decryptionKeys: privateKey,
        format: 'binary'
    });

    const response = await fetch(serverurl + '/download_stream/' + stream_token);
    const buffer = stringToBuffer(await response.text());

    const encrypted = await openpgp.readMessage({
        binaryMessage: buffer
    });

    const decrypted = await openpgp.decrypt({
        message: encrypted,
        passwords: bufferToString(decryptedKey.data),
        format: 'binary'
    });

/*    const fileMessage = await openpgp.readMessage({
        binaryMessage: decrypted
    });

    const signature = await openpgp.readSignature({
        binarySignature: stringToBuffer(filesig)
    });

    const ver = await openpgp.verify({
        message: fileMessage,
        signature,
        verificationKeys: publicKey
    });

    if (!await ver.signatures[0].verified) {
        throw new Error('File signature invalid');
    }*/

    const buf = decrypted.data;

    fs.writeFile(localPath, buf, (err) => {
        if (err) throw err;
    });
}

async function getPath(remotePath: string) {
    const body = {
        token,
        path: remotePath
    };

    const response = await sendRequest('get_path', body);
    const files = JSON.parse(await response.text());

    const dirs = remotePath.split('/');

    if (dirs[0] === 'private') {
        const table: {
            name: string,
            date: string,
            isFolder: string
        }[] = [];

        for (let i = 0; i < files.length; i += 4) {
            const actual_path = dirs.length <= 2 ? files[i] :
                dirs.slice(1).join('/') + '/' + files[i];
            cachedFiles.set(actual_path, {
                date: files[i + 1],
                key: stringToBuffer(base64decode(files[i + 2])),
                isFolder: files[i + 3] === 0 ? false : true
            });

            table[i / 4] = {
                name: files[i],
                date: strftime('%F %T', new Date(files[i + 1] * 1000)),
                isFolder: files[i + 3] === 0 ? "No" : "Yes"
            };
        }

        return table;
    }

    const table: {
        name: string,
        date: string,
        isFolder: string,
        sharer: string
    }[] = [];

    for (let i = 0; i < files.length; i += 5) {
        sharedCachedFiles.set('shared/' + files[i], {
            date: files[i + 1],
            key: stringToBuffer(base64decode(files[i + 2])),
            isFolder: files[i + 3] === 0 ? false : true,
            username: files[i + 4]
        });

        table[i / 5] = {
            name: files[i],
            date: strftime('%F %T', new Date(files[i + 1] * 1000)),
            isFolder: files[i + 3] === 0 ? "No" : "Yes",
            sharer: files[i + 4]
        };
    }

    return table;
}

async function shareFile(sharedUser: string, remotePath: string) {
    const public_key = base64decode(JSON.parse(await (await sendRequest('get_public_key', {
        user_name: sharedUser
    })).text()).pk);

    const userkey = (await openpgp.readKey({
        armoredKey: public_key
    })).toPublic();

    const key = cachedFiles.get(remotePath)?.key;
    if (key === undefined) {
        throw new Error('path doesn\'t exist');
    }

    const keyMessage = await openpgp.readMessage({
        binaryMessage: key
    });

    const decryptedKey = await openpgp.decrypt({
        message: keyMessage,
        decryptionKeys: privateKey,
        format: 'binary'
    });

//  Create OpenPGP message
    const keyMessage2 = await openpgp.createMessage({
        binary: decryptedKey.data as Uint8Array
    });

//  Encrypt encryption key using shared user's public key
    const encrypted = await openpgp.encrypt({
        message: keyMessage2,
        encryptionKeys: userkey,
        format: 'binary'
    });

    return await sendRequest('share_file', {
        token,
        path: remotePath,
        username: sharedUser,
        file_key: base64encode(bufferToString(encrypted)),
        sharesig: 'J'
    });
}

const api = {
    register,
    login,
    logout,
    restoreSession,
    listSavedAccounts,
    restoreUserSession,
    uploadFile,
    downloadFile,
    getPath,
    shareFile,
    closeDHT
};

export {api as default};
