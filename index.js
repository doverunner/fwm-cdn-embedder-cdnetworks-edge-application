import { config } from './config.js';
import doveRunnerAes from './wmt/doveRunnerAes.js';
import akamaiWmt from './wmt/akamaiWmt.js';
import wmUtil from './watermark-util/wmUtil.js';
import {validateConfig} from './watermark-util/validateConfig.js';

validateConfig(config);

const isWatermarkedPrefix = (requestPrefixFolder) => {
    const { prefixFolder } = config;
    if (Array.isArray(prefixFolder)) {
        return prefixFolder.includes(requestPrefixFolder);
    } else {
        return prefixFolder === requestPrefixFolder;
    }
}

const generateResponse = async (finalRequestPath, request) => {
    const origin = request.url.match(/^[a-z][a-z0-9+.-]*:\/\/[^/]+/i)[0];
    const { search } = new URL(request.url);
    const range = request.headers.get('range');

    return fetch(origin + finalRequestPath + search, {
        method: request.method,
        headers: range ? { range } : {},
    });
}

const handleRequest = async (request) => {
    const url = new URL(request.url);
    console.log('request: ' + url.pathname);

    try {
        let finalRequestPath;
        let uriSegments = url.pathname.split('/');
        const prefixFolder = uriSegments[1];

        if (prefixFolder.startsWith('wmt:')) {
            finalRequestPath = await akamaiWmt.getContentUrl(url.pathname, uriSegments, config);
        } else if (isWatermarkedPrefix(prefixFolder)) {
            const { modifiedUriSegments, hasRevokeToken } = wmUtil.removeRevokeToken(uriSegments);
            uriSegments = modifiedUriSegments;
            const requestPath = '/' + uriSegments.slice(1).join('/');

            finalRequestPath = await doveRunnerAes.getContentUrl(
                requestPath, uriSegments, prefixFolder, config, hasRevokeToken
            );
        }

        if (finalRequestPath && 'string' !== typeof finalRequestPath) {
            console.log(`response: ${finalRequestPath.status} ${finalRequestPath.statusDescription}`);
            return new Response(finalRequestPath.statusDescription, {
                status: Number(finalRequestPath.status)
            });
        }

        if (!finalRequestPath) {
            console.log('response: ' + url.pathname);
            return await fetch(request);
        }

        console.log('response: ' + finalRequestPath);
        return await generateResponse(finalRequestPath, request);
    } catch (e) {
        console.error('watermark request rejected: ' + e.name);
        return new Response('Forbidden', { status: 403 });
    }
}

addEventListener('fetch', (event) => {
    event.respondWith(handleRequest(event.request));
});
