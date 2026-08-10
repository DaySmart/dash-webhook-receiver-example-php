<?php

declare(strict_types=1);

namespace App\Services;

use App\Exceptions\WebhookVerificationException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class JwksCache
{
    public function fetch(string $url): array
    {
        $ttl = (int) config('webhook-receiver.jwks_cache_ttl', 3600);
        $cacheKey = 'webhook_receiver.jwks.'.md5($url);

        return Cache::remember($cacheKey, $ttl, function () use ($url) {
            $response = Http::timeout(5)->get($url);

            if (! $response->successful()) {
                throw new WebhookVerificationException(
                    "Failed to fetch JWKS from {$url}: HTTP {$response->status()}"
                );
            }

            $data = $response->json();

            if (! isset($data['keys']) || ! is_array($data['keys'])) {
                throw new WebhookVerificationException('Invalid JWKS response: missing keys array');
            }

            return $data;
        });
    }

    public function findKey(array $jwks, string $kid): array
    {
        foreach ($jwks['keys'] as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }

        throw new WebhookVerificationException("No JWKS key found with kid=\"{$kid}\"");
    }
}
