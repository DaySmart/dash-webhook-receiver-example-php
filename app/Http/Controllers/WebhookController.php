<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\WebhookEvent;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Receives a signed CloudEvents v1.0 webhook delivery.
 *
 * VerifyWebhookSignature middleware checks the Content-Digest, RFC 9421
 * signature, and replay window, but does not reject failed deliveries itself
 * — it flags the failure via the "webhook_signature_error" request attribute
 * and passes the request through. This controller stores every delivery
 * either way (with signature_verified reflecting the outcome) so failed
 * deliveries remain visible for audit, and only then responds 401/204.
 */
class WebhookController extends Controller
{
    public function __invoke(Request $request): Response
    {
        $webhookId = $request->header('WebHook-ID');
        $signatureError = $request->attributes->get('webhook_signature_error');

        // Idempotency: the sender retries deliveries with the same WebHook-ID.
        // Skip re-storing, but keep responding based on the original signature
        // outcome so a legitimately failed retry still sees a 401.
        if ($webhookId && WebhookEvent::where('webhook_id', $webhookId)->exists()) {
            return $this->response($signatureError);
        }

        $payload = $request->json()->all();

        WebhookEvent::create([
            'webhook_id' => $webhookId,
            'event_type' => $payload['type'] ?? null,
            'source' => $payload['source'] ?? null,
            'subject' => $payload['subject'] ?? null,
            'payload' => $payload,
            'headers' => $request->headers->all(),
            'received_at' => now(),
            'signature_verified' => $signatureError === null,
        ]);

        return $this->response($signatureError);
    }

    private function response(?string $signatureError): Response
    {
        if ($signatureError !== null) {
            return response()->json(['error' => $signatureError], 401);
        }

        return response('', 204);
    }
}
