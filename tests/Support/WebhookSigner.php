<?php

declare(strict_types=1);

namespace Tests\Support;

/**
 * Test-only counterpart to App\Services\WebhookSignatureVerifier: generates a
 * keypair, exposes it as a JWKS, and signs requests per RFC 9421 so feature
 * tests can exercise the real verification pipeline end to end.
 */
class WebhookSigner
{
    private \OpenSSLAsymmetricKey $privateKey;

    private string $ed25519SecretKey = '';

    private array $jwk;

    public string $kid;

    public string $alg;

    private function __construct(private readonly int $ecKeySize = 0) {}

    public static function rsa(string $kid = 'test-rsa-key'): self
    {
        $signer = new self;

        $res = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        openssl_pkey_export($res, $pem);
        $signer->privateKey = openssl_pkey_get_private($pem);

        $details = openssl_pkey_get_details($signer->privateKey);

        $signer->kid = $kid;
        $signer->alg = 'rsa-v1_5-sha256';
        $signer->jwk = [
            'kty' => 'RSA',
            'kid' => $kid,
            'n' => self::b64u($details['rsa']['n']),
            'e' => self::b64u($details['rsa']['e']),
        ];

        return $signer;
    }

    public static function ec(string $curve, string $kid = 'test-ec-key'): self
    {
        [$curveName, $alg, $keySize] = match ($curve) {
            'P-256' => ['prime256v1', 'ecdsa-p256-sha256', 32],
            'P-384' => ['secp384r1', 'ecdsa-p384-sha384', 48],
        };

        $signer = new self($keySize);

        $res = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curveName,
        ]);
        openssl_pkey_export($res, $pem);
        $signer->privateKey = openssl_pkey_get_private($pem);

        $details = openssl_pkey_get_details($signer->privateKey);

        $signer->kid = $kid;
        $signer->alg = $alg;
        $signer->jwk = [
            'kty' => 'EC',
            'kid' => $kid,
            'crv' => $curve,
            'x' => self::b64u(str_pad($details['ec']['x'], $keySize, "\x00", STR_PAD_LEFT)),
            'y' => self::b64u(str_pad($details['ec']['y'], $keySize, "\x00", STR_PAD_LEFT)),
        ];

        return $signer;
    }

    public static function edwards25519(string $kid = 'test-ed25519-key'): self
    {
        $signer = new self;

        $keyPair = sodium_crypto_sign_keypair();
        $signer->ed25519SecretKey = sodium_crypto_sign_secretkey($keyPair);
        $publicKey = sodium_crypto_sign_publickey($keyPair);

        $signer->kid = $kid;
        $signer->alg = 'ed25519';
        $signer->jwk = [
            'kty' => 'OKP',
            'kid' => $kid,
            'crv' => 'Ed25519',
            'x' => self::b64u($publicKey),
        ];

        return $signer;
    }

    public function jwks(): array
    {
        return ['keys' => [$this->jwk]];
    }

    /**
     * Sign a request and return the headers to attach to it.
     *
     * $path may include a query string (e.g. "/webhooks?b=2&a=1") — it's
     * signed in exactly that order, mirroring Dash's use of parse_url's raw,
     * unsorted query string rather than a re-sorted one.
     *
     * $components overrides the default covered-component list (useful for
     * covering an extra header, e.g. "webhook-id"). Any non-derived component
     * needs a matching entry in $extraHeaders; entries there are also sent as
     * literal request headers, EXCEPT when a component references one that
     * isn't in $extraHeaders at all — that signs an empty-string line without
     * ever sending the header, for exercising "component missing entirely".
     *
     * @return array<string,string>
     */
    public function sign(
        string $method,
        string $host,
        string $path,
        string $body,
        ?int $created = null,
        array $overrideParams = [],
        ?array $components = null,
        array $extraHeaders = [],
    ): array {
        $digest = 'sha-256=:'.base64_encode(hash('sha256', $body, true)).':';

        $components ??= ['@method', '@authority', '@path', '@query', 'content-digest'];
        $componentList = '('.implode(' ', array_map(fn ($c) => '"'.$c.'"', $components)).')';

        $params = array_merge([
            'created' => $created ?? time(),
            'keyid' => '"'.$this->kid.'"',
            'alg' => '"'.$this->alg.'"',
        ], $overrideParams);

        $paramsStr = '';
        foreach ($params as $key => $value) {
            $paramsStr .= ";{$key}={$value}";
        }

        $innerList = $componentList.$paramsStr;

        $queryPos = strpos($path, '?');
        $pathOnly = $queryPos === false ? $path : substr($path, 0, $queryPos);
        $query = $queryPos === false ? '' : substr($path, $queryPos + 1);

        $lines = [];
        foreach ($components as $component) {
            $value = match ($component) {
                '@method' => strtoupper($method),
                '@authority' => $host,
                '@path' => $pathOnly,
                '@query' => '?'.$query,
                'content-digest' => $digest,
                default => $extraHeaders[$component] ?? '',
            };
            $lines[] = '"'.$component.'": '.$value;
        }
        $lines[] = '"@signature-params": '.$innerList;
        $base = implode("\n", $lines);

        $headers = [
            'Content-Digest' => $digest,
            'Signature-Input' => "sig1={$innerList}",
            'Signature' => 'sig1=:'.base64_encode($this->rawSign($base)).':',
        ];

        foreach ($extraHeaders as $name => $value) {
            $headers[$name] = $value;
        }

        return $headers;
    }

    private function rawSign(string $base): string
    {
        if ($this->ed25519SecretKey !== '') {
            return sodium_crypto_sign_detached($base, $this->ed25519SecretKey);
        }

        if ($this->ecKeySize === 0) {
            openssl_sign($base, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

            return $signature;
        }

        $algo = $this->ecKeySize === 48 ? OPENSSL_ALGO_SHA384 : OPENSSL_ALGO_SHA256;
        openssl_sign($base, $der, $this->privateKey, $algo);

        return $this->derEcdsaToRaw($der, $this->ecKeySize);
    }

    /**
     * openssl_sign() returns DER-encoded ECDSA signatures (SEQUENCE of two
     * INTEGERs); RFC 9421 requires raw fixed-width r||s. Mirrors the inverse
     * of WebhookSignatureVerifier::rawEcdsaToDer().
     */
    private function derEcdsaToRaw(string $der, int $keySize): string
    {
        $pos = 0;
        $sequence = self::readDerTlv($der, $pos);

        $innerPos = 0;
        $r = self::readDerTlv($sequence, $innerPos);
        $s = self::readDerTlv($sequence, $innerPos);

        return self::padInt($r, $keySize).self::padInt($s, $keySize);
    }

    private static function padInt(string $int, int $size): string
    {
        $int = ltrim($int, "\x00");
        if ($int === '') {
            $int = "\x00";
        }

        return str_pad($int, $size, "\x00", STR_PAD_LEFT);
    }

    private static function readDerTlv(string $der, int &$pos): string
    {
        $pos++; // skip tag byte
        $lenByte = ord($der[$pos]);
        $pos++;

        if ($lenByte < 0x80) {
            $len = $lenByte;
        } else {
            $len = 0;
            for ($i = 0, $numBytes = $lenByte & 0x7F; $i < $numBytes; $i++) {
                $len = ($len << 8) | ord($der[$pos]);
                $pos++;
            }
        }

        $value = substr($der, $pos, $len);
        $pos += $len;

        return $value;
    }

    private static function b64u(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
