import * as openpgp from 'openpgp';
const globalsalt: string = '';

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

    return String(signature);
}

const api = {
    register
};

export {api as default};
