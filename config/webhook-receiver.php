<?php

return [
    /*
     * URL of the sender's published JWKS endpoint, e.g.
     * https://api.example.com/.well-known/jwks.json
     * Required for RFC 9421 signature verification.
     */
    'sender_jwks_url' => env('WEBHOOK_SENDER_JWKS_URL'),

    /*
     * Expected WebHook-Request-Origin value in validation handshakes — a
     * hostname such as api.example.com, NOT a URL. A handshake requesting
     * a different origin is refused. Set to * to accept and echo back any
     * origin.
     */
    'sender_origin' => env('WEBHOOK_SENDER_ORIGIN', '*'),

    /*
     * Maximum delivery rate (requests/minute) to advertise during handshake.
     * The sender stores and honours this limit per subscription.
     */
    'allowed_rate' => env('WEBHOOK_ALLOWED_RATE', 1000),

    /*
     * Maximum acceptable clock skew (seconds) between the 'created' timestamp
     * in Signature-Input and the receiver's current time.  Protects against
     * signature replay attacks.
     */
    'replay_window' => env('WEBHOOK_REPLAY_WINDOW', 300),

    /*
     * Optional shared Bearer secret set on the subscription.
     * When non-null, the Authorization: Bearer <secret> header is verified
     * in constant time as a secondary check alongside the RFC 9421 signature.
     */
    'secret' => env('WEBHOOK_SECRET'),

    /*
     * How long to cache the sender's JWKS response (seconds).
     * A signature whose "keyid" isn't in the cached JWKS triggers one
     * uncached refetch before being rejected, so key rotation is picked up
     * immediately without waiting out the TTL. Don't set this too high in
     * the hope of "stability" — it only postpones that refetch path, it
     * doesn't avoid it.
     */
    'jwks_cache_ttl' => env('WEBHOOK_JWKS_CACHE_TTL', 3600),
];
