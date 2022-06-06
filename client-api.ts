import * as openpgp from 'openpgp';
import * as bcrypt from 'bcrypt';
import fetch from 'electron-fetch';

const globalsalt: string = '';
const serverurl: string = '';

function base64encode(str: string) {
    return Buffer.from(str, 'utf8').toString('base64');
}

function base64decode(base64str: string) {
    return Buffer.from(base64str, 'base64').toString('utf8');
}

async function register(username: string, password: string) {
//  Generate key pair
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'rsa', // Type of the key
        rsaBits: 4096, // RSA key size (defaults to 4096 bits)
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
    register
};

export {api as default};
