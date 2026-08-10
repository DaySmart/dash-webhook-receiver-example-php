<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Handles the OPTIONS validation handshake (Webhook Protocol Binding §3).
 *
 * The sender performs this request once when a subscription is created to
 * verify that the target endpoint is willing to accept deliveries.  The
 * receiver responds with WebHook-Allowed-Origin and WebHook-Allowed-Rate to
 * grant permission.
 */
class WebhookHandshakeController extends Controller
{
    public function __invoke(Request $request): Response
    {
        $requestOrigin = $request->header('WebHook-Request-Origin', '*');
        $configOrigin = config('webhook-receiver.sender_origin', '*');

        // Echo back the sender's origin when we accept any origin, otherwise
        // respond with the specific origin we are configured to allow.
        $allowedOrigin = ($configOrigin === '*') ? $requestOrigin : $configOrigin;
        $allowedRate = (string) config('webhook-receiver.allowed_rate', 1000);

        return response('', 200)
            ->header('WebHook-Allowed-Origin', $allowedOrigin)
            ->header('WebHook-Allowed-Rate', $allowedRate);
    }
}
