<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\WebhookEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Testing\TestResponse;
use Tests\Support\WebhookSigner;
use Tests\TestCase;

class WebhookDeliveryTest extends TestCase
{
    use RefreshDatabase;

    private const HOST = 'webhook-receiver.test';

    private const JWKS_URL = 'https://sender.example.com/.well-known/jwks.json';

    protected function setUp(): void
    {
        parent::setUp();

        Config::set('webhook-receiver.sender_jwks_url', self::JWKS_URL);
    }

    private function fakeJwks(WebhookSigner $signer): void
    {
        Http::fake([
            self::JWKS_URL => Http::response($signer->jwks(), 200),
        ]);
    }

    private function deliver(array $headers, string $body, string $path = '/webhooks', ?string $host = null): TestResponse
    {
        $server = $this->transformHeadersToServerVars(array_merge(['Content-Type' => 'application/json'], $headers));

        return $this->call('POST', 'http://'.($host ?? self::HOST).$path, [], [], [], $server, $body);
    }

    public function test_valid_rsa_signed_request_is_accepted_and_stored(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers', 'subject' => 'cust_1']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-rsa-1';

        $this->deliver($headers, $body)->assertStatus(204);

        $this->assertDatabaseHas('webhook_events', [
            'webhook_id' => 'delivery-rsa-1',
            'event_type' => 'customer.registered',
            'signature_verified' => true,
        ]);
    }

    public function test_valid_ec_p256_signed_request_is_accepted(): void
    {
        $signer = WebhookSigner::ec('P-256');
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.updated', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-ec-1';

        $this->deliver($headers, $body)->assertStatus(204);

        $this->assertDatabaseHas('webhook_events', ['webhook_id' => 'delivery-ec-1']);
    }

    public function test_valid_ed25519_signed_request_is_accepted(): void
    {
        $signer = WebhookSigner::edwards25519();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.updated', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-ed25519-1';

        $this->deliver($headers, $body)->assertStatus(204);

        $this->assertDatabaseHas('webhook_events', ['webhook_id' => 'delivery-ed25519-1']);
    }

    public function test_tampered_body_is_rejected(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-tampered';

        $response = $this->deliver($headers, json_encode(['type' => 'customer.deleted']));

        $response->assertStatus(401);
        $this->assertDatabaseHas('webhook_events', [
            'webhook_id' => 'delivery-tampered',
            'signature_verified' => false,
        ]);
    }

    public function test_rejected_delivery_is_logged(): void
    {
        Log::spy();

        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-tampered-log';

        $this->deliver($headers, json_encode(['type' => 'customer.deleted']))->assertStatus(401);

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(fn (string $message, array $context) => $message === 'Webhook signature verification failed'
                && $context['webhook_id'] === 'delivery-tampered-log'
                && str_contains($context['reason'], 'Content-Digest mismatch'));
    }

    public function test_missing_content_digest_header_is_rejected(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        unset($headers['Content-Digest']);

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_stale_signature_outside_replay_window_is_rejected(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body, created: time() - 3600);

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_unknown_keyid_is_rejected(): void
    {
        $signer = WebhookSigner::rsa('key-actually-used-to-sign');
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body, overrideParams: [
            'keyid' => '"key-not-in-jwks"',
        ]);

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_bearer_secret_mismatch_is_rejected_when_configured(): void
    {
        Config::set('webhook-receiver.secret', 'super-secret-value');

        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['Authorization'] = 'Bearer wrong-secret';

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_matching_bearer_secret_is_accepted_when_configured(): void
    {
        Config::set('webhook-receiver.secret', 'super-secret-value');

        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['Authorization'] = 'Bearer super-secret-value';
        $headers['WebHook-ID'] = 'delivery-with-bearer';

        $this->deliver($headers, $body)->assertStatus(204);
    }

    public function test_retried_delivery_with_same_webhook_id_is_deduplicated(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-dedup';

        $this->deliver($headers, $body)->assertStatus(204);
        $this->deliver($headers, $body)->assertStatus(204);

        $this->assertSame(1, WebhookEvent::where('webhook_id', 'delivery-dedup')->count());
    }

    public function test_retried_failed_delivery_with_same_webhook_id_still_returns_401_without_duplicating(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-dedup-failed';

        $tamperedBody = json_encode(['type' => 'customer.deleted']);

        $this->deliver($headers, $tamperedBody)->assertStatus(401);
        $this->deliver($headers, $tamperedBody)->assertStatus(401);

        $this->assertSame(1, WebhookEvent::where('webhook_id', 'delivery-dedup-failed')->count());
    }

    public function test_retry_that_would_now_verify_still_returns_401_because_the_first_attempt_failed(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $webhookId = 'delivery-fail-then-success';
        $validBody = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $validHeaders = $signer->sign('POST', self::HOST, '/webhooks', $validBody);
        $validHeaders['WebHook-ID'] = $webhookId;

        // First attempt: body doesn't match what was signed — fails verification.
        $this->deliver($validHeaders, json_encode(['type' => 'customer.deleted']))->assertStatus(401);

        // "Retry" with the same WebHook-ID, this time correctly signed — the
        // first outcome still wins, since a real retry never fixes itself.
        $this->deliver($validHeaders, $validBody)->assertStatus(401);

        $this->assertSame(1, WebhookEvent::where('webhook_id', $webhookId)->count());
        $this->assertDatabaseHas('webhook_events', [
            'webhook_id' => $webhookId,
            'signature_verified' => false,
        ]);
    }

    public function test_retry_that_would_now_fail_still_returns_204_because_the_first_attempt_succeeded(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $webhookId = 'delivery-success-then-fail';
        $validBody = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $validHeaders = $signer->sign('POST', self::HOST, '/webhooks', $validBody);
        $validHeaders['WebHook-ID'] = $webhookId;

        // First attempt verifies correctly and is stored.
        $this->deliver($validHeaders, $validBody)->assertStatus(204);

        // A second request reusing the same WebHook-ID but with a tampered
        // body must not flip the stored outcome to failed.
        $this->deliver($validHeaders, json_encode(['type' => 'customer.deleted']))->assertStatus(204);

        $this->assertSame(1, WebhookEvent::where('webhook_id', $webhookId)->count());
        $this->assertDatabaseHas('webhook_events', [
            'webhook_id' => $webhookId,
            'signature_verified' => true,
        ]);
    }

    public function test_rejected_delivery_response_body_does_not_leak_verification_detail(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);

        $response = $this->deliver($headers, json_encode(['type' => 'customer.deleted']));

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'Webhook verification failed']);
    }

    public function test_authorization_and_cookie_headers_are_redacted_before_storage(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-with-cookie';
        $headers['Authorization'] = 'Bearer super-secret-subscription-token';
        $headers['Cookie'] = 'session=super-secret-session-value';

        $this->deliver($headers, $body)->assertStatus(204);

        $stored = WebhookEvent::where('webhook_id', 'delivery-with-cookie')->firstOrFail();

        $this->assertSame(['[redacted]'], $stored->headers['authorization']);
        $this->assertSame(['[redacted]'], $stored->headers['cookie']);
        $this->assertStringNotContainsString('super-secret-subscription-token', json_encode($stored->headers));
        $this->assertStringNotContainsString('super-secret-session-value', json_encode($stored->headers));
    }

    public function test_jwks_endpoint_returning_a_server_error_is_a_500_not_a_401(): void
    {
        Http::fake([
            self::JWKS_URL => Http::response('service unavailable', 503),
        ]);

        $signer = WebhookSigner::rsa();
        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);

        // A 500 tells the sender to retry with backoff instead of abandoning
        // the delivery, since a transient JWKS outage is not a fake signature.
        $this->deliver($headers, $body)->assertStatus(500);
    }

    public function test_unknown_keyid_triggers_a_fresh_jwks_fetch_before_being_rejected(): void
    {
        $oldSigner = WebhookSigner::rsa('key-before-rotation');
        $newSigner = WebhookSigner::rsa('key-after-rotation');

        Http::fake([
            self::JWKS_URL => Http::sequence()
                ->push($oldSigner->jwks(), 200)
                ->push($newSigner->jwks(), 200),
        ]);

        $body = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);

        // Warm the cache with the pre-rotation JWKS.
        $warmHeaders = $oldSigner->sign('POST', self::HOST, '/webhooks', $body);
        $warmHeaders['WebHook-ID'] = 'delivery-before-rotation';
        $this->deliver($warmHeaders, $body)->assertStatus(204);

        // Sender rotates keys; our cache still only knows the old key. The
        // unknown "keyid" should trigger one uncached refetch rather than an
        // immediate 401.
        $rotatedHeaders = $newSigner->sign('POST', self::HOST, '/webhooks', $body);
        $rotatedHeaders['WebHook-ID'] = 'delivery-after-rotation';
        $this->deliver($rotatedHeaders, $body)->assertStatus(204);
    }

    public function test_query_string_is_signed_in_its_original_unsorted_order(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        // Symfony/Laravel's Request::getQueryString() alphabetically re-sorts
        // query params for cache-key normalisation; Dash signs the raw,
        // unsorted query string from parse_url. b before a would only survive
        // verification if the raw, unsorted string is what gets compared.
        $headers = $signer->sign('POST', self::HOST, '/webhooks?b=2&a=1', $body);
        $headers['WebHook-ID'] = 'delivery-query-order';

        $this->deliver($headers, $body, path: '/webhooks?b=2&a=1')->assertStatus(204);
    }

    public function test_authority_component_is_lowercased_and_default_port_is_omitted(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        // Dash signs the lowercased host with no port (443 is its default and
        // always omitted) — the actual request may arrive with a differently
        // cased Host header and an explicit default port.
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-authority-case';

        $this->deliver($headers, $body, host: strtoupper(self::HOST).':443')
            ->assertStatus(204);
    }

    public function test_authority_component_includes_a_non_default_port(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST.':8443', '/webhooks', $body);
        $headers['WebHook-ID'] = 'delivery-authority-port';

        $this->deliver($headers, $body, host: self::HOST.':8443')
            ->assertStatus(204);
    }

    public function test_alg_that_does_not_match_the_resolved_key_is_rejected(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        // Claim an EC algorithm while actually RSA-signing. openssl_verify()
        // infers RSA-vs-ECDSA from the key, not from "alg", so without an
        // explicit cross-check this verifies successfully — it shouldn't.
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body, overrideParams: [
            'alg' => '"ecdsa-p256-sha256"',
        ]);

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_jwks_key_marked_for_encryption_is_not_accepted_for_signature_verification(): void
    {
        $signer = WebhookSigner::rsa();
        $key = $signer->jwks()['keys'][0];
        $key['use'] = 'enc';

        Http::fake([
            self::JWKS_URL => Http::response(['keys' => [$key]], 200),
        ]);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body);

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_expired_signature_is_rejected_even_when_created_is_within_the_replay_window(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body, overrideParams: [
            'expires' => (string) (time() - 60),
        ]);

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_missing_covered_component_is_rejected_instead_of_treated_as_empty(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        // "x-never-sent" is covered by the signature but the header is never
        // actually attached to the request — RFC 9421 requires a hard fail
        // here, not silently treating the missing header as an empty string.
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body, components: [
            '@method', '@authority', '@path', '@query', 'content-digest', 'x-never-sent',
        ]);

        $this->deliver($headers, $body)->assertStatus(401);
    }

    public function test_webhook_id_header_covered_by_the_signature_is_verified(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $webhookId = 'delivery-webhook-id-covered';
        $body = json_encode(['type' => 'customer.registered', 'source' => 'https://api.daysmartrecreation.com/customers']);

        // "webhook-id" is covered in the signature base — the covered-component
        // list is driven entirely by Signature-Input, so this needs no code change,
        // just confirmation it actually works.
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body, components: [
            '@method', '@authority', '@path', '@query', 'content-digest', 'webhook-id',
        ], extraHeaders: ['webhook-id' => $webhookId]);
        $headers['WebHook-ID'] = $webhookId;

        $this->deliver($headers, $body)->assertStatus(204);
        $this->assertDatabaseHas('webhook_events', ['webhook_id' => $webhookId, 'signature_verified' => true]);
    }

    public function test_tampering_the_webhook_id_header_when_covered_by_the_signature_is_rejected(): void
    {
        $signer = WebhookSigner::rsa();
        $this->fakeJwks($signer);

        $body = json_encode(['type' => 'customer.registered']);
        $headers = $signer->sign('POST', self::HOST, '/webhooks', $body, components: [
            '@method', '@authority', '@path', '@query', 'content-digest', 'webhook-id',
        ], extraHeaders: ['webhook-id' => 'delivery-original']);

        // Swap in a different WebHook-ID than the one that was actually signed.
        $headers['WebHook-ID'] = 'delivery-swapped';

        $this->deliver($headers, $body)->assertStatus(401);
    }
}
