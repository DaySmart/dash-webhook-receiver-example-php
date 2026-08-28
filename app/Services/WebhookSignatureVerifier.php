<?php

declare(strict_types=1);

namespace App\Services;

use App\Exceptions\WebhookVerificationException;
use Illuminate\Http\Request;

/**
 * Verifies incoming webhook deliveries per the HTTP Webhook Protocol Binding
 * spec.  Steps follow RFC 9421 (HTTP Message Signatures) and RFC 9530
 * (Content-Digest).
 */
readonly class WebhookSignatureVerifier
{
    public function __construct(private JwksCache $jwksCache) {}

    /**
     * Verify all authenticity checks on an incoming POST delivery.
     * Throws WebhookVerificationException on any failure.
     */
    public function verify(Request $request): void
    {
        $rawBody = $request->getContent();

        // 1. Bind verification to the exact bytes that arrived.
        $this->verifyContentDigest($rawBody, $request->header('Content-Digest'));

        // 2. Parse Signature-Input to learn what was signed and by which key.
        $signatureInputHeader = $request->header('Signature-Input')
            ?? throw new WebhookVerificationException('Missing Signature-Input header');

        [$label, $components, $params, $innerList] = $this->parseSignatureInput($signatureInputHeader);

        // 3. Reject stale or future-dated signatures.
        $created = isset($params['created']) ? (int) $params['created'] : null;
        if ($created === null) {
            throw new WebhookVerificationException('Missing "created" parameter in Signature-Input');
        }
        $this->verifyReplayWindow($created);

        // 3b. Reject an explicit expiry if the sender sent one. Dash doesn't
        // send "expires" today, but the field is part of RFC 9421 and a
        // reference verifier shouldn't silently ignore it if it shows up.
        if (isset($params['expires'])) {
            $expires = (int) $params['expires'];
            if (time() > $expires) {
                throw new WebhookVerificationException(
                    "Signature has expired: expires={$expires}, now=".time()
                );
            }
        }

        // 4. Resolve the signing key from the sender's published JWKS.
        $keyId = isset($params['keyid']) ? trim($params['keyid'], '"') : null;
        if ($keyId === null) {
            throw new WebhookVerificationException('Missing "keyid" parameter in Signature-Input');
        }
        $alg = isset($params['alg']) ? trim($params['alg'], '"') : 'rsa-v1_5-sha256';

        $jwksUrl = config('webhook-receiver.sender_jwks_url');
        if (empty($jwksUrl)) {
            throw new WebhookVerificationException('WEBHOOK_SENDER_JWKS_URL is not configured');
        }
        $jwk = $this->jwksCache->resolveKey($jwksUrl, $keyId);
        $this->assertAlgMatchesKey($alg, $jwk);

        // 5. Reconstruct the exact byte string the sender signed.
        $base = $this->reconstructSignatureBase($components, $innerList, $request);

        // 6. Cryptographically verify the signature.
        $signatureHeader = $request->header('Signature')
            ?? throw new WebhookVerificationException('Missing Signature header');
        $this->verifySignature($base, $signatureHeader, $label, $jwk, $alg);

        // 7. Optional secondary check: Bearer secret (constant-time comparison).
        $secret = config('webhook-receiver.secret');
        if (! empty($secret)) {
            $auth = $request->header('Authorization', '');
            $token = str_starts_with($auth, 'Bearer ') ? substr($auth, 7) : '';
            if (! hash_equals($secret, $token)) {
                throw new WebhookVerificationException('Bearer secret mismatch');
            }
        }
    }

    // -------------------------------------------------------------------------
    // Step 1 — Content-Digest (RFC 9530)
    // -------------------------------------------------------------------------

    private function verifyContentDigest(string $rawBody, ?string $header): void
    {
        if ($header === null) {
            throw new WebhookVerificationException('Missing Content-Digest header');
        }

        // Expected format: sha-256=:<base64>:
        if (! preg_match('/sha-256=:([A-Za-z0-9+\/=]+):/', $header, $m)) {
            throw new WebhookVerificationException('Invalid Content-Digest format (expected sha-256=:<base64>:)');
        }

        $expected = base64_encode(hash('sha256', $rawBody, true));

        if (! hash_equals($expected, $m[1])) {
            throw new WebhookVerificationException('Content-Digest mismatch — body may have been modified in transit');
        }
    }

    // -------------------------------------------------------------------------
    // Step 2 — Signature-Input parsing (RFC 8941 structured field)
    // -------------------------------------------------------------------------

    /**
     * @return array{string, list<string>, array<string,string>, string} [label, coveredComponents, params, innerListValue]
     */
    private function parseSignatureInput(string $header): array
    {
        // Format: sig1=("comp1" "comp2");created=123;keyid="kid";alg="alg"
        // We use the first label only.
        if (! preg_match('/^([a-z0-9_-]+)=(\([^)]*\)(?:;[^,]*)?)(?:,|$)/i', $header, $m)) {
            throw new WebhookVerificationException('Cannot parse Signature-Input header');
        }

        $label = $m[1];
        $innerList = trim($m[2]); // everything from "(" onward for this label

        // Extract component identifiers from the inner list
        if (! preg_match('/^\(([^)]*)\)/', $innerList, $cm)) {
            throw new WebhookVerificationException('Cannot parse component list in Signature-Input');
        }

        $components = [];
        $compStr = trim($cm[1]);
        if ($compStr !== '') {
            preg_match_all('/"([^"]+)"/', $compStr, $compMatches);
            $components = $compMatches[1];
        }

        // Extract parameters (;key=value or ;key="value")
        $paramsStr = substr($innerList, strlen($cm[0]));
        $params = [];
        preg_match_all('/;([a-z0-9_-]+)=("(?:[^"\\\\]|\\\\.)*"|[^\s;,]+)/i', $paramsStr, $pm, PREG_SET_ORDER);
        foreach ($pm as $match) {
            $params[$match[1]] = $match[2];
        }

        return [$label, $components, $params, $innerList];
    }

    // -------------------------------------------------------------------------
    // Step 3 — Replay window
    // -------------------------------------------------------------------------

    private function verifyReplayWindow(int $created): void
    {
        $window = (int) config('webhook-receiver.replay_window', 300);
        $drift = abs(time() - $created);

        if ($drift > $window) {
            throw new WebhookVerificationException(
                "Signature is outside the replay window: created={$created}, now=".time()
                .", drift={$drift}s > {$window}s"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Step 5 — Signature base reconstruction (RFC 9421 §2.5)
    // -------------------------------------------------------------------------

    /**
     * Build the byte string that was signed.  Each covered component becomes a
     * "<name>: <value>\n" line, followed by the "@signature-params" line.
     *
     * The innerList value MUST be taken verbatim from the Signature-Input
     * header — re-serialising it would change the bytes and break verification.
     */
    private function reconstructSignatureBase(
        array $components,
        string $innerList,
        Request $request
    ): string {
        $lines = [];

        foreach ($components as $component) {
            $value = match ($component) {
                '@method' => strtoupper($request->method()),
                '@authority' => $this->authorityComponent($request),
                '@path' => $request->getPathInfo() ?: '/',
                // Dash signs the raw query string (from parse_url, original
                // order) — NOT Request::getQueryString(), which Symfony
                // alphabetically re-sorts for cache-key normalisation and
                // would silently break signatures on any query string.
                '@query' => '?'.($request->server->get('QUERY_STRING') ?? ''),
                default => $request->header($component)
                    ?? throw new WebhookVerificationException("Missing covered component \"{$component}\" required by Signature-Input"),
            };

            $lines[] = '"'.$component.'": '.$value;
        }

        $lines[] = '"@signature-params": '.$innerList;

        // RFC 9421 §2.5: lines are joined by "\n" with NO trailing newline
        // after the final "@signature-params" line.
        return implode("\n", $lines);
    }

    /**
     * Dash lowercases the host and appends ":<port>" unless the port is 443
     * (its default). Match that exactly — the Host header alone is neither
     * lowercased nor consistently ported.
     */
    private function authorityComponent(Request $request): string
    {
        $parts = parse_url('http://'.$request->header('host', ''));
        $host = strtolower($parts['host'] ?? '');
        $port = $parts['port'] ?? null;

        return ($port !== null && $port !== 443) ? "{$host}:{$port}" : $host;
    }

    // -------------------------------------------------------------------------
    // Step 4b — alg/key consistency (RFC 9421 §3.3: alg is advisory metadata,
    // not itself authenticated by the signature, so it must be cross-checked
    // against the actual key rather than trusted to pick the verification
    // routine)
    // -------------------------------------------------------------------------

    /**
     * openssl_verify() infers the signature scheme from the key type, not
     * from $alg — so a request claiming alg=ecdsa-p256-sha256 while actually
     * RSA-signed still verifies successfully once $alg has merely selected
     * the SHA-256 digest. Reject any mismatch between the declared alg and
     * what the resolved key can actually produce before verifying.
     */
    private function assertAlgMatchesKey(string $alg, array $jwk): void
    {
        $kty = $jwk['kty'] ?? null;

        $expected = match ($kty) {
            'RSA' => 'rsa-v1_5-sha256',
            'EC' => match ($jwk['crv'] ?? null) {
                'P-256' => 'ecdsa-p256-sha256',
                'P-384' => 'ecdsa-p384-sha384',
                default => null,
            },
            'OKP' => match ($jwk['crv'] ?? null) {
                'Ed25519' => 'ed25519',
                default => null,
            },
            default => null,
        };

        if ($expected === null || $alg !== $expected) {
            throw new WebhookVerificationException(
                "Signature alg \"{$alg}\" does not match the resolved key (kty=".($kty ?? 'null').')'
            );
        }
    }

    // -------------------------------------------------------------------------
    // Step 6 — Signature verification
    // -------------------------------------------------------------------------

    private function verifySignature(
        string $base,
        string $sigHeader,
        string $label,
        array $jwk,
        string $alg
    ): void {
        // Extract this label's base64-encoded signature bytes: sig1=:<b64>:
        $pattern = '/'.preg_quote($label, '/').'=:([A-Za-z0-9+\/=]+):/';
        if (! preg_match($pattern, $sigHeader, $m)) {
            throw new WebhookVerificationException("Cannot parse Signature header for label \"{$label}\"");
        }

        $sigBytes = base64_decode($m[1], true);
        if ($sigBytes === false) {
            throw new WebhookVerificationException('Invalid base64 in Signature header');
        }

        // EdDSA signs the message directly (no pre-hash), so it doesn't go
        // through openssl_verify/PEM like RSA and ECDSA below — verify
        // straight off the raw JWK public key bytes with libsodium instead.
        if (($jwk['kty'] ?? 'RSA') === 'OKP') {
            $this->verifyEddsaSignature($base, $sigBytes, $jwk, $alg);

            return;
        }

        $pem = $this->jwkToPem($jwk);
        $pubKey = openssl_pkey_get_public($pem);
        if ($pubKey === false) {
            throw new WebhookVerificationException('Failed to load public key from JWK');
        }

        // RFC 9421 ECDSA signatures are raw r||s, not DER — PHP's openssl_verify needs DER.
        $kty = $jwk['kty'] ?? 'RSA';
        if ($kty === 'EC') {
            $keySize = match ($alg) {
                'ecdsa-p256-sha256' => 32,
                'ecdsa-p384-sha384' => 48,
                default => throw new WebhookVerificationException("Unsupported EC algorithm: {$alg}"),
            };
            $sigBytes = $this->rawEcdsaToDer($sigBytes, $keySize);
        }

        $opensslAlg = match ($alg) {
            'rsa-v1_5-sha256' => OPENSSL_ALGO_SHA256,
            'ecdsa-p256-sha256' => OPENSSL_ALGO_SHA256,
            'ecdsa-p384-sha384' => OPENSSL_ALGO_SHA384,
            default => throw new WebhookVerificationException("Unsupported algorithm: {$alg}"),
        };

        $result = openssl_verify($base, $sigBytes, $pubKey, $opensslAlg);

        if ($result !== 1) {
            throw new WebhookVerificationException('RFC 9421 signature verification failed');
        }
    }

    /**
     * RFC 9421 §3.3.7 EdDSA using curve edwards25519 (alg "ed25519").
     */
    private function verifyEddsaSignature(string $base, string $sigBytes, array $jwk, string $alg): void
    {
        if ($alg !== 'ed25519') {
            throw new WebhookVerificationException("Unsupported OKP algorithm: {$alg}");
        }

        $crv = $jwk['crv'] ?? throw new WebhookVerificationException('OKP JWK missing "crv"');
        if ($crv !== 'Ed25519') {
            throw new WebhookVerificationException("Unsupported OKP curve: {$crv}");
        }

        $publicKey = $this->b64uDecode($jwk['x'] ?? throw new WebhookVerificationException('OKP JWK missing "x"'));

        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new WebhookVerificationException('Invalid Ed25519 public key length');
        }

        if (strlen($sigBytes) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new WebhookVerificationException('Invalid Ed25519 signature length');
        }

        if (! sodium_crypto_sign_verify_detached($sigBytes, $base, $publicKey)) {
            throw new WebhookVerificationException('RFC 9421 signature verification failed');
        }
    }

    /**
     * RFC 9421 ECDSA signatures are serialized as raw r||s (each component
     * padded to the key size).  PHP's openssl_verify expects DER-encoded
     * ECDSA signatures (SEQUENCE { INTEGER r, INTEGER s }).
     */
    private function rawEcdsaToDer(string $raw, int $keySize): string
    {
        if (strlen($raw) !== 2 * $keySize) {
            throw new WebhookVerificationException(
                'Invalid ECDSA signature length: expected '.(2 * $keySize).' bytes, got '.strlen($raw)
            );
        }

        $r = ltrim(substr($raw, 0, $keySize), "\x00") ?: "\x00";
        $s = ltrim(substr($raw, $keySize), "\x00") ?: "\x00";

        // Prepend 0x00 if the high bit is set (ASN.1 INTEGER is signed)
        if (ord($r[0]) & 0x80) {
            $r = "\x00".$r;
        }
        if (ord($s[0]) & 0x80) {
            $s = "\x00".$s;
        }

        return $this->asn1Tlv(0x30,
            $this->asn1Tlv(0x02, $r).
            $this->asn1Tlv(0x02, $s)
        );
    }

    // -------------------------------------------------------------------------
    // JWK → PEM conversion (hand-rolled ASN.1 DER SubjectPublicKeyInfo)
    // -------------------------------------------------------------------------

    private function jwkToPem(array $jwk): string
    {
        return match ($jwk['kty'] ?? null) {
            'RSA' => $this->rsaJwkToPem($jwk),
            'EC' => $this->ecJwkToPem($jwk),
            default => throw new WebhookVerificationException('Unsupported JWK kty: '.($jwk['kty'] ?? 'null')),
        };
    }

    /**
     * RSA JWK → SubjectPublicKeyInfo PEM.
     *
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *   algorithm  AlgorithmIdentifier (OID rsaEncryption + NULL)
     *   publicKey  BIT STRING { SEQUENCE { INTEGER n, INTEGER e } }
     * }
     */
    private function rsaJwkToPem(array $jwk): string
    {
        $n = $this->b64uDecode($jwk['n'] ?? throw new WebhookVerificationException('RSA JWK missing "n"'));
        $e = $this->b64uDecode($jwk['e'] ?? throw new WebhookVerificationException('RSA JWK missing "e"'));

        // ASN.1 INTEGER must be non-negative; prepend 0x00 if high bit is set
        if (ord($n[0]) & 0x80) {
            $n = "\x00".$n;
        }
        if (ord($e[0]) & 0x80) {
            $e = "\x00".$e;
        }

        $rsaPublicKey = $this->asn1Tlv(0x30,
            $this->asn1Tlv(0x02, $n).
            $this->asn1Tlv(0x02, $e)
        );

        // OID 1.2.840.113549.1.1.1  (rsaEncryption)
        $algId = $this->asn1Tlv(0x30,
            $this->asn1Tlv(0x06, $this->encodeOid('1.2.840.113549.1.1.1')).
            $this->asn1Tlv(0x05, '') // NULL
        );

        $spki = $this->asn1Tlv(0x30,
            $algId.
            $this->asn1Tlv(0x03, "\x00".$rsaPublicKey) // BIT STRING, 0 unused bits
        );

        return $this->wrapPem($spki, 'PUBLIC KEY');
    }

    /**
     * EC JWK → SubjectPublicKeyInfo PEM.
     *
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *   algorithm  AlgorithmIdentifier (OID ecPublicKey + curve OID)
     *   publicKey  BIT STRING { 0x04 || x || y }
     * }
     */
    private function ecJwkToPem(array $jwk): string
    {
        $crv = $jwk['crv'] ?? throw new WebhookVerificationException('EC JWK missing "crv"');
        $x = $this->b64uDecode($jwk['x'] ?? throw new WebhookVerificationException('EC JWK missing "x"'));
        $y = $this->b64uDecode($jwk['y'] ?? throw new WebhookVerificationException('EC JWK missing "y"'));

        [$curveOid, $keySize] = match ($crv) {
            'P-256' => ['1.2.840.10045.3.1.7', 32],
            'P-384' => ['1.3.132.0.34',         48],
            default => throw new WebhookVerificationException("Unsupported EC curve: {$crv}"),
        };

        // Pad x/y to the expected key size
        $x = str_pad($x, $keySize, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, $keySize, "\x00", STR_PAD_LEFT);

        // OID 1.2.840.10045.2.1  (ecPublicKey)
        $algId = $this->asn1Tlv(0x30,
            $this->asn1Tlv(0x06, $this->encodeOid('1.2.840.10045.2.1')).
            $this->asn1Tlv(0x06, $this->encodeOid($curveOid))
        );

        // Uncompressed EC point: 0x04 || x || y
        $spki = $this->asn1Tlv(0x30,
            $algId.
            $this->asn1Tlv(0x03, "\x00\x04".$x.$y) // BIT STRING, 0 unused bits
        );

        return $this->wrapPem($spki, 'PUBLIC KEY');
    }

    // -------------------------------------------------------------------------
    // Low-level ASN.1 DER helpers
    // -------------------------------------------------------------------------

    /** Encode one ASN.1 TLV (Tag-Length-Value) element in DER. */
    private function asn1Tlv(int $tag, string $value): string
    {
        $len = strlen($value);

        $lenDer = match (true) {
            $len < 0x80 => chr($len),
            $len < 0x100 => "\x81".chr($len),
            $len < 0x10000 => "\x82".chr($len >> 8).chr($len & 0xFF),
            default => throw new WebhookVerificationException('ASN.1 value too large to DER-encode'),
        };

        return chr($tag).$lenDer.$value;
    }

    /** Encode a dotted OID string to DER bytes (tag excluded — use asn1Tlv(0x06, ...)). */
    private function encodeOid(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));

        // First two components are packed into one octet: 40*first + second
        $bytes = chr($parts[0] * 40 + $parts[1]);

        for ($i = 2, $n = count($parts); $i < $n; $i++) {
            $val = $parts[$i];

            if ($val === 0) {
                $bytes .= "\x00";

                continue;
            }

            // Base-128 big-endian with continuation bits on all but the last octet
            $encoded = '';
            while ($val > 0) {
                $encoded = chr($val & 0x7F).$encoded;
                $val >>= 7;
            }
            for ($j = 0, $last = strlen($encoded) - 1; $j < $last; $j++) {
                $encoded[$j] = chr(ord($encoded[$j]) | 0x80);
            }
            $bytes .= $encoded;
        }

        return $bytes;
    }

    private function wrapPem(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\n"
            .chunk_split(base64_encode($der), 64, "\n")
            ."-----END {$label}-----\n";
    }

    /** Decode a base64url string (RFC 4648 §5) to raw bytes. */
    private function b64uDecode(string $input): string
    {
        $padded = str_pad(strtr($input, '-_', '+/'), strlen($input) + (4 - strlen($input) % 4) % 4, '=');
        $decoded = base64_decode($padded, true);

        if ($decoded === false) {
            throw new WebhookVerificationException('Invalid base64url encoding in JWK field');
        }

        return $decoded;
    }
}
