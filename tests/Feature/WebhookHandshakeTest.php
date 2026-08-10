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

    public function test_it_responds_with_the_configured_origin_when_restricted(): void
    {
        Config::set('webhook-receiver.sender_origin', 'https://allowed-sender.example.com');

        $server = $this->transformHeadersToServerVars([
            'WebHook-Request-Origin' => 'https://someone-else.example.com',
        ]);
        $response = $this->call('OPTIONS', '/webhooks', [], [], [], $server);

        $response->assertStatus(200);
        $response->assertHeader('WebHook-Allowed-Origin', 'https://allowed-sender.example.com');
    }
}
