import unlabeledAVariantModule from '../watermark-util/unlabeledAVariantModule.js';
import wmUtil from '../watermark-util/wmUtil.js';
import watermarkUtil from '../watermark-util/index.js';

const getContentUrl = async (requestPath, uriSegments, config) => {
    if (!config.wmtPublicKey || !config.wmtPassword) {
        console.error('Please set wmtPublicKey or wmtPassword in config.js.');
        return {status: '403', statusDescription: 'Watermark token support is not configured'};
    }
    if ('unlabeled_a_variant' !== config.type.toLowerCase()) {
        console.error('AkamaiWmt supports only unlabeled_a_variant.');
        return {status: '403', statusDescription: 'Watermark token support is not configured'};
    }

    const jwt = uriSegments[1].substring(4);

    const watermark = await parseWatermarkToken(jwt, config.wmtPublicKey, config.wmtPassword);

    if (!watermark) {
        return {status: '403', statusDescription: 'Invalid watermark token'};
    }

    const requestedFileName = requestPath.split('/').pop();
    if (wmUtil.findBlockedPrefix(requestedFileName, 2)) {
        return {status: '403', statusDescription: 'Unsafe file path request detected.'};
    }

    const contentPath = requestPath.substring(uriSegments[1].length + 1);

    const firstSegmentNumber = /\.ts(\?|$)/i.test(contentPath) ? 1 : 0;

    return unlabeledAVariantModule.createWatermarkUrl(contentPath, '', {
        watermark_data: btoa(watermark),
        sync_skip_bit: -1, renditions: 2, lead_in: 0,
        first_segment_number: firstSegmentNumber
    });
}

const parseWatermarkToken = async (jwt, wmtPublicKey, passwd) => {
    let watermarkData;
    let step = 'signature verification';
    try {
        if (!(await hasValidSignature(jwt, wmtPublicKey))) {
            throw new Error('signature does not match the configured wmtPublicKey');
        }

        const payload = getPayloadFromJwt(jwt);

        step = 'payload decryption';

        const aesKey = await watermarkUtil.sha256Digest(passwd);
        const aesIv = watermarkUtil.base64ToBytes(payload['wmidivb64']);

        let binaryPattern = await watermarkUtil.aesDecrypt(payload['wmidctb64'], aesKey, aesIv);
        binaryPattern = binaryPattern.replace(/A/gi, '0').replace(/B/gi, '1');
        watermarkData = binaryPattern;
        console.log('watermark pattern: ' + watermarkData);
    } catch (e) {
        console.error(`akamai watermark token rejected at ${step}: ${e.message}`);
    }
    return watermarkData;
}

const getSecuredInputFromJwt = (jwt) => jwt.split('.', 2).join('.');

const getSignatureFromJwt = (jwt) => jwt.split('.')[2];

const getPayloadFromJwt = (jwt) =>
    JSON.parse(new TextDecoder().decode(watermarkUtil.base64ToBytes(jwt.split('.')[1])));

const hasValidSignature = async (jwt, wmtPublicKey) => {
    const signature = watermarkUtil.base64ToBytes(getSignatureFromJwt(jwt));
    const data = new TextEncoder().encode(getSecuredInputFromJwt(jwt));

    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    let pemContents = wmtPublicKey;

    if (wmtPublicKey.includes(pemHeader)) {
        pemContents = wmtPublicKey.substring(
            wmtPublicKey.indexOf(pemHeader) + pemHeader.length,
            wmtPublicKey.indexOf(pemFooter)
        );
    }

    const cryptoKey = await crypto.subtle.importKey(
        'spki',
        watermarkUtil.base64ToBytes(pemContents.replace(/\s/g, '')),
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
    );

    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, data);
}

export default { getContentUrl };
