# DoveRunner Forensic Watermark CDN Embedder Sample for CDNetworks Edge Application

> **A reference implementation.** Fork this sample and adapt it to your own delivery setup — the
> function you deploy is yours to operate.
>
> - **Docs**: https://docs.doverunner.com/content-security/forensic-watermarking/embedding/
> - **Support**: https://doverunner.zendesk.com
> - **Security**: report a vulnerability through support
> - **Copyright**: ⓒ 2026 DoveRunner. All Rights Reserved. (doverunner.com)

This project serves as a sample implementation for embedding forensic watermarks using
**CDNetworks Edge Application** (Edge Cloud Apps). The function runs on the CDN edge, resolves the
watermark token in the request path, and forwards the request to the rendition path it selects.
It does not store or serve content itself — the CDN fetches the rewritten path from your origin.

For more information, refer to the [CDNetworks Edge Application documentation](https://documents.cdnetworks.com/document/edgeapplication/ea-overview).

## Configuration
### Configure config.js
Update `config.js` with your specific settings:

```javascript
export const config = {
    "aesKey": "YOUR_DOVERUNER_SITE_KEY",
    "type" : "unlabeled_a_variant",
    "availableInterval": 60,
    "prefixFolder": ["folder1", "folder2"],
    "wmtPublicKey": "YOUR_PUBLIC_KEY", // PEM format public key for Akamai WMT
    "wmtPassword": "YOUR_PASSWORD" // Password for WMT token generation/verification
}
```

**wmt_type**: Indicates whether the issued token format is AES-encrypted or JWT. This corresponds to the specification provided when requesting the watermark token.
- [Watermark Token Request Specification](https://docs.doverunner.com/content-security/forensic-watermarking/embedding/session-manager/#api-data-json-format)

| Key                 | wmt_type | Description                                                                                                                                                                                                                                         |
|:--------------------|:---------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `aesKey`            | aes      | The Site Key issued by the DoveRunner ContentSecurity Service.                                                                                                                                                                                      |
| `type`              | aes, jwt | The [Watermark File Folder Structure](#watermark-file-folder-structure). Default: `unlabeled_a_variant`.                                                                                                                                            |
| `availableInterval` | aes      | Token validity window in **minutes** (0 disables the check).                                                                                                                                                                                                |
| `prefixFolder`      | aes      | The top-level folder containing watermark files. Corresponds to `prefix_folder` in the [Watermark Token Request Specification](https://docs.doverunner.com/content-security/forensic-watermarking/embedding/session-manager/#api-data-json-format). |
| `wmtPublicKey`      | jwt      | PEM format public key for Akamai WMT.                                                                                                                                                                                                               |
| `wmtPassword`       | jwt      | Password for WMT token generation/verification.                                                                                                                                                                                                     |

## Watermark Forms and Token Payload

The DoveRunner AES watermark token carried in the request path decrypts to a JSON payload.
Its fields drive every rewrite decision the embedder makes:

| Field                  | Description                                                                                     |
|:-----------------------|:------------------------------------------------------------------------------------------------|
| `watermark_data`       | Base64 of the finished `0`/`1` symbol pattern.                                                  |
| `streaming_format`     | `dash` or `hls`. Informational — it no longer selects the first segment.                        |
| `first_segment_number` | Segment number the pattern is aligned to. Required — a token without it is rejected with `403`. |
| `timestamp`            | Issue time, `YYYY-MM-DDThh:mm:ssZ`, checked against `availableInterval`.                        |
| `revoke_flag`          | Whether a revoke token must accompany the request.                                              |
| `sync_skip_bit`        | Sync offset added to the segment number; `-1` when inactive. `0` is a valid, active offset.     |
| `renditions`           | Physical rendition count, `2` or `4`. Absent means `2`.                                         |
| `lead_in`              | Unmarked lead-in before the first marked segment, in symbols. Absent means `4`; `0` is valid.   |

The last two fields select the **watermark form**. A Long-Form token may omit them — the
defaults reproduce the Long-Form constants:

| Form       | `renditions` | `lead_in` |
|:-----------|-------------:|----------:|
| Long-Form  |            2 |         4 |
| Short-Form |            2 |         0 |
| Micro-Form |            4 |         0 |

**How symbols map to segments.** One symbol spans one media segment. One segment carries
`log2(renditions)` bits of the pattern: 1 bit with two renditions, 2 bits with four. The first
`lead_in` symbols play unmarked; after them the pattern repeats for the rest of the stream.

**How symbols name renditions.** Under `unlabeled_a_variant` the symbol becomes a file name
prefix; under `directory_prefix` and `aws` it becomes a path segment:

| Symbol | `unlabeled_a_variant` prefix       | `directory_prefix` / `aws` segment |
|:------:|:-----------------------------------|:-----------------------------------|
| `0`    | *(none — the unlabeled A variant)* | `/0`                               |
| `1`    | `b.`                               | `/1`                               |
| `2`    | `c.` — four renditions only        | `/2`                               |
| `3`    | `d.` — four renditions only        | `/3`                               |

Direct requests for a marked variant file are refused with `403` according to the rendition
count: two renditions block the `b.` prefix, four block `b.`, `c.` and `d.`.

The Akamai WMT route is different: that token carries only the symbol pattern, and the sample
resolves it with fixed Long-Form settings (`renditions` 2) and no lead-in.

## Watermark File Folder Structure

### directory_prefix

- Distinguishes renditions by a `0`–`3` directory segment.

#### Example

```text
/wm-contents/output_path/cid/{0/1}/dash/stream.mpd
/wm-contents/output_path/cid/{0/1}/dash/video/0/seg-125.m4s
/wm-contents/output_path/cid/{0/1}/hls/master.m3u8
/wm-contents/output_path/cid/{0/1}/hls/video/0/0/stream.m3u8
/wm-contents/output_path/cid/{0/1}/hls/video/0/0/segment-125.ts
```

### unlabeled_a_variant

- A/B files exist in the same folder and are distinguished by filename prefixes.
- With two renditions the marked file is prefixed `b.`; with four renditions the
  prefixes are `b.`, `c.` and `d.`.

#### Example

```text
/wm-contents/output_path/cid/dash/stream.mpd
/wm-contents/output_path/cid/dash/video/0/seg-125.m4s
/wm-contents/output_path/cid/dash/video/0/b.seg-125.m4s
/wm-contents/output_path/cid/hls/master.m3u8
/wm-contents/output_path/cid/hls/video/0/0/stream.m3u8
/wm-contents/output_path/cid/hls/video/0/0/segment-125.ts
/wm-contents/output_path/cid/hls/video/0/0/b.segment-125.ts
```

### aws

- For content packaged by AWS Elemental MediaConvert. The `0`/`1` rendition directory sits
  directly above the streaming-format directory:

```text
/wm-contents/output_path/{0/1}/dash/stream.mpd
/wm-contents/output_path/{0/1}/hls/master.m3u8
```

The packager must encode the content twice — once into the `0` (unmarked) destination and once
into the `1` (marked) destination — name the manifest `stream` for DASH and `master` for HLS, and
use a GOP size of 60.

## Packaging Preconditions

The embedder picks a rendition from the **request path alone**. A path it cannot read is passed
through unmarked — playback still succeeds, but those segments carry no fingerprint and cannot be
traced. Your packager output must satisfy every rule below.

1. **End every media segment name with its segment number.** The number is taken after the last
   `_` or `-`, whichever comes later in the name, and everything following that separator must
   be digits. A name that adds a suffix after the number cannot be read and is served unmarked.
   Good `segment-125.ts`, `video_1080p-9.ts` · Bad `segment-125_backup.ts`

2. **End initialisation segment names with a lowercase `_init`, never with a number.** `_init` is
   the only spelling every `type` layout accepts. An init file whose name ends in a digit is read
   as a media segment instead, and whenever the symbol for that number is not `0` it is rewritten
   to a rendition path that does not exist and answers `404`.
   Good `video_init.mp4` · Bad `init-9.m4s`

3. **Keep the content path below the token deep enough.** Under `directory_prefix` the rendition
   directory is inserted 5 levels above `.ts`, `.m4s`, `.mp4`, `.aac`, `stream.m3u8` and
   `iframes.m3u8`, 4 levels above `subtitle.m3u8`, `.vtt` and any `.m4s`/`.mp4` directly inside a
   `subtitle` directory, and 2 levels above `.mpd` and any `.m3u8` whose name contains `master`;
   under `aws` it is always 2 levels. The path must hold at least that many parts,
   counting the file name — a shallower path receives no rendition directory at all.
   `unlabeled_a_variant` is unaffected, because it marks the file name rather than the path.
   Good `/{token}/out/cid/hls/video/avc1/1/segment-125.ts` · Bad `/{token}/cid/hls/segment-125.ts`

4. **Name HLS playlists as the layout expects.** Under `directory_prefix` an `.m3u8` name is
   recognised only when it contains `master`, or is exactly `stream.m3u8`, `iframes.m3u8` or
   `subtitle.m3u8`; the match is case-sensitive. Any other name falls back to a path that inserts
   `/0` above **every** `dash`, `hls` or `cmaf` directory in the path, and inserts nothing at all
   when the path contains none of those. `.mpd` manifests may carry any name.
   Good `master.m3u8`, `stream.m3u8` · Bad `index.m3u8`, `playlist.m3u8`

5. **Package to discrete segment files.** The rendition is chosen from the file name alone; no
   part of that decision looks at the `Range` header. An HLS `#EXT-X-BYTERANGE` layout — one file
   addressed by byte offsets — therefore presents a single name, and a single rendition, for the
   whole stream. Such a stream carries no usable fingerprint.
   Good `segment-1.ts`, `segment-2.ts`, … · Bad one `main.ts` plus `#EXT-X-BYTERANGE`

## Usage

The function intercepts client requests and routes them based on the URL structure:

1.  **Akamai WMT**: If the path starts with `wmt:`, it uses `akamaiWmt.js` to verify the token and rewrite the path.
2.  **DoveRunner AES**: If the path matches one of the `prefixFolder` entries, it uses `doveRunnerAes.js` to decrypt the watermark data and generate the appropriate content path.

**Token lifetime on the Akamai WMT route.** The sample checks only the RS256 signature of a
`wmt:` token — it enforces no expiry, and `availableInterval` applies to the DoveRunner AES route
only. Bound the URL or token lifetime upstream, for example with Akamai edge token authorization
or short-lived signed URLs: if nothing upstream bounds it, a leaked `wmt:` URL stays valid until
the signing key is rotated.

## Request flow

`event.request` is read-only in Edge Application, so the function cannot change the path in place.
It resolves the rendition path and fetches it **on the same domain**, keeping the method, the
`Range` header and the query string. A rejected token is answered with `403` without contacting the
origin.

A subrequest made by the function does not run the trigger again: it goes through the CDN cache to
the domain's origin, using the domain's origin settings (protocol, host header). Because the
rewritten path carries no token, viewers that resolve to the same rendition of the same segment
share one cache entry. The token itself is validated on every request the trigger matches, so an
expired token is refused even when the segment is cached.

Use the trigger's path condition to run the function only on the watermark folders
(for example `/wm-contents/*`). Other paths then bypass the function entirely.

## Runtime notes

The Edge Application runtime differs from the web platform in ways this sample works around:

- `new URL(path, base).href` does not return a string, and `fetch()` rejects it. Build URLs by
  string concatenation; `new URL(request.url)` with a single argument works.
- `Headers` has no `entries()` or `forEach()`. Read headers with `get()`, and pass request headers
  to `fetch()` as a plain object.
- Web Crypto (`crypto.subtle`) provides AES-CBC and RSASSA-PKCS1-v1_5 on HTTP and HTTPS domains.

## Deployment

### Prerequisites
- A **CDNetworks account** with Edge Application enabled
- A CDN domain (Content Acceleration or Media Acceleration Live Broadcast) whose origin holds the
  watermarked renditions

### Step 1: Build a single file

CloudIDE takes the function as one `index.js`. Set your values in `config.js`, then bundle:

```bash
npm install
npm run bundle
```

This writes `dist/index.js`. Each GitHub Release also attaches
`doverunner_fwm_embedder_cdnetworks.<version>.zip` with the same bundle — if you use it, set your
values in the `config` object at the top of its `index.js` instead.

### Step 2: Create the function

1. In **Edge Application → Function List**, create a function without a template.
2. In CloudIDE, replace `index.js` with `dist/index.js` — paste its contents, or upload the file
   from the Explorer (**Upload...**).
3. Click **save and test**. This commits the code; `Cmd+S` / `Ctrl+S` alone does not.

### Step 3: Deploy and bind a trigger

1. Deploy from **Grayscale Deployment**, then check that the version in the deployment record
   changed. An unchanged version means the code was not committed in Step 2.
2. In **Trigger List → Add**, select your domain, add a path condition for your watermark folders
   (for example `/wm-contents/*`), and select the function.

To update the function later, repeat Step 2.2 to Step 3.1.

### Additional Resources

- [Edge Application overview](https://documents.cdnetworks.com/document/edgeapplication/ea-overview)
- [Add triggers](https://documents.cdnetworks.com/document/edgeapplication/add-triggers)
- [Web Crypto](https://documents.cdnetworks.com/document/edgeapplication/web-crypto)
