import * as openpgp from 'openpgp';
import * as bcrypt from 'bcrypt';

const globalsalt: string = '';
const serverurl = '';

async function register(username : string, password : string) {
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'rsa', // Type of the key
        rsaBits: 4096, // RSA key size (defaults to 4096 bits)
        userIDs: [{ name: username, email: username + '@myoud.org' }], // you can pass multiple user IDs
        format: 'object' // output key format, defaults to 'armored'
    });

    const message = await openpgp.createMessage({text: username + globalsalt});
    const signature = await openpgp.sign({
        message,
        signingKeys: privateKey,
        detached: true
    });

    const salt2 = await bcrypt.genSalt();
    const encryptionKey = await bcrypt.hash(password, salt2);

    const privateKeyMessage = await openpgp.createMessage({
        text: privateKey.armor()
    });

    const encrypted_private_key = await openpgp.encrypt({
        message: privateKeyMessage,
        passwords: encryptionKey
    });

    const hashed_password = await bcrypt.hash(password,
        await bcrypt.genSalt());

    const requestBody = {
        user_name: username,
        public_key: publicKey.armor(),
        signature: String(signature),
        encrypted_private_key: String(encrypted_private_key),
        hashed_password,
        salt2
    };
    
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
