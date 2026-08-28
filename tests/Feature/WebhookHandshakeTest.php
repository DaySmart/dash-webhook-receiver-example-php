<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class WebhookHandshakeTest extends TestCase
{
    public function test_it_echoes_the_requested_origin_when_any_origin_is_allowed(): void
    {
        Config::set('webhook-receiver.sender_origin', '*');
        Config::set('webhook-receiver.allowed_rate', 500);

        $server = $this->transformHeadersToServerVars([
            'WebHook-Request-Origin' => 'https://sender.example.com',
        ]);
        $response = $this->call('OPTIONS', '/webhooks', [], [], [], $server);

        $response->assertStatus(200);
        $response->assertHeader('WebHook-Allowed-Origin', 'https://sender.example.com');
        $response->assertHeader('WebHook-Allowed-Rate', '500');
    }

    public function test_it_accepts_the_handshake_when_the_requested_origin_matches_the_pinned_origin(): void
    {
        Config::set('webhook-receiver.sender_origin', 'api.example.com');
        Config::set('webhook-receiver.allowed_rate', 500);

        $server = $this->transformHeadersToServerVars([
            'WebHook-Request-Origin' => 'api.example.com',
        ]);
        $response = $this->call('OPTIONS', '/webhooks', [], [], [], $server);

        $response->assertStatus(200);
        $response->assertHeader('WebHook-Allowed-Origin', 'api.example.com');
        $response->assertHeader('WebHook-Allowed-Rate', '500');
    }

    public function test_it_refuses_the_handshake_when_the_requested_origin_does_not_match_the_pinned_origin(): void
    {
        // Per the Webhook Protocol Binding spec, WebHook-Allowed-Origin must be
        // exactly the requested origin or "*" — never a different value chosen
        // by the receiver. A mismatch must be refused by omitting the consent
        // headers, not by echoing back our own pinned origin.
        Config::set('webhook-receiver.sender_origin', 'api.example.com');

        $server = $this->transformHeadersToServerVars([
            'WebHook-Request-Origin' => 'someone-else.example.com',
        ]);
        $response = $this->call('OPTIONS', '/webhooks', [], [], [], $server);

        $response->assertStatus(200);
        $response->assertHeaderMissing('WebHook-Allowed-Origin');
        $response->assertHeaderMissing('WebHook-Allowed-Rate');
    }
}
