<?php

declare(strict_types=1);

namespace App\Services;

use App\Exceptions\JwksUnavailableException;
use App\Exceptions\WebhookVerificationException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class JwksCache
{
    /**
     * Resolve the JWK for $kid, refreshing the cache once if it's missing.
     *
     * A cached JWKS won't contain a key rotated in after it was fetched, so a
     * miss on the first (cached) lookup doesn't necessarily mean the kid is
     * bogus — it may just mean our cache predates the sender's rotation.
     * Only report an unknown key (401, no retry) after a fresh fetch also
     * fails to find it.
     */
    public function resolveKey(string $url, string $kid): array
    {
        $jwk = $this->findKey($this->fetch($url), $kid);

        if ($jwk !== null) {
            return $jwk;
        }

        $jwk = $this->findKey($this->fetch($url, forceRefresh: true), $kid);

        if ($jwk === null) {
            throw new WebhookVerificationException("No JWKS key found with kid=\"{$kid}\"");
        }

        return $jwk;
    }

    private function fetch(string $url, bool $forceRefresh = false): array
    {
        $ttl = (int) config('webhook-receiver.jwks_cache_ttl', 3600);
        $cacheKey = 'webhook_receiver.jwks.'.md5($url);

        if ($forceRefresh) {
            Cache::forget($cacheKey);
        }

        return Cache::remember($cacheKey, $ttl, function () use ($url) {
            // Connection errors (timeouts, DNS, refused) already throw
            // Illuminate\Http\Client\ConnectionException, which isn't caught
            // by VerifyWebhookSignature and so becomes a 500 — matching how
            // we want HTTP-level failures below to behave too.
            $response = Http::timeout(5)->get($url);

            if (! $response->successful()) {
                throw new JwksUnavailableException(
                    "Failed to fetch JWKS from {$url}: HTTP {$response->status()}"
                );
            }

            $data = $response->json();

            if (! isset($data['keys']) || ! is_array($data['keys'])) {
                throw new JwksUnavailableException('Invalid JWKS response: missing keys array');
            }

            return $data;
        });
    }

    private function findKey(array $jwks, string $kid): ?array
    {
        foreach ($jwks['keys'] as $key) {
            if (($key['kid'] ?? null) !== $kid) {
                continue;
            }

            // A JWKS can publish encryption keys alongside signing keys.
            // Dash's exported keys are "use": "sig", but only trust that
            // explicitly rather than assuming an unmarked key is safe to
            // verify with — skip anything declared for another purpose.
            if (($key['use'] ?? 'sig') !== 'sig') {
                continue;
            }

            return $key;
        }

        return null;
    }
}
