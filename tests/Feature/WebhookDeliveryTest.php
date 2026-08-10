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

    private function deliver(array $headers, string $body): TestResponse
    {
        $server = $this->transformHeadersToServerVars(array_merge(['Content-Type' => 'application/json'], $headers));

        return $this->call('POST', 'http://'.self::HOST.'/webhooks', [], [], [], $server, $body);
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
}
