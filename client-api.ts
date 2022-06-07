import * as openpgp from 'openpgp';
import * as bcrypt from 'bcrypt';
import fetch from 'electron-fetch';
const DHT = require('bittorrent-dht');
const ed = require('bittorrent-dht-sodium');
const dht = new DHT({ verify: ed.verify });

const globalsalt: string = '';
const serverurl: string = '';
const dhtport: number = 0;

function base64encode(str: string) {
    return Buffer.from(str, 'utf8').toString('base64');
}

function base64decode(base64str: string) {
    return Buffer.from(base64str, 'base64').toString('utf8');
}

function closeDHT() {
    dht.destroy();
}

async function register(username: string, password: string) {
//  Generate key pair
    const {privateKey: privateKeyBinary, publicKey: publicKeyBinary} = await openpgp.generateKey({
        type: 'ecc', // Type of the key
        curve: 'ed25519', // Curve, dht requires ed25519
        userIDs: [{ name: username, email: username + '@myoud.org' }], // you can pass multiple user IDs
        format: 'binary' // output key format, defaults to 'armored'
    });

    const privateKey = await openpgp.readPrivateKey({
        binaryKey: privateKeyBinary
    });
    const publicKey = privateKey.toPublic();

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
    const value = Buffer.alloc(200).fill(username);
    const opts = {
        k: Buffer.from(publicKeyBinary),
        sign: function(buf: Buffer) {
            return ed.sign(buf, privateKeyBinary);
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
    const registerResponse = await fetch(
        serverurl + '/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        }
    );

    return registerResponse;
}

const api = {
    register,
    closeDHT
};

export {api as default};
