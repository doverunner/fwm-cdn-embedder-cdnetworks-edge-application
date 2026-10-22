const AES_IV = new TextEncoder().encode('0123456789abcdef');

async function importKey(key) {
    const keyBytes = key instanceof Uint8Array ? key : new TextEncoder().encode(key);

    return crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-CBC' },
        false,
        ['encrypt', 'decrypt']
    );
}

async function aesDecrypt(watermarkData, aesKey, aesIv = AES_IV) {
    const cryptoKey = await importKey(aesKey);

    const plaintextBuf = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: aesIv },
        cryptoKey,
        base64ToBytes(watermarkData)
    );

    return new TextDecoder().decode(new Uint8Array(plaintextBuf));
}

async function sha256Digest(passwd) {
    const data = new TextEncoder().encode(passwd);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    return new Uint8Array(hashBuffer);
}

const isTokenFresh = (timestamp, interval) => {
    if (0 === interval) {
        return true;
    }
    const now = new Date();
    const checkTime = new Date(timestamp);
    const currentMilliSeconds = now.getTime();
    const checkMilliSeconds = checkTime.getTime();
    const period = (currentMilliSeconds - checkMilliSeconds) / 1000;

    return (interval * 60) > period && period > 0;
}

function base64ToBytes(b64) {
    b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

export default { aesDecrypt, sha256Digest, isTokenFresh, base64ToBytes };
