<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\WebhookEvent;
use Illuminate\Database\QueryException;
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
 *
 * Retries reuse the sender's WebHook-ID. The FIRST stored outcome for a given
 * WebHook-ID is authoritative for every response after it — a retry is never
 * re-verified or re-answered on its own merits, even if this particular
 * attempt's signature would have verified differently.
 */
class WebhookController extends Controller
{
    /**
     * Headers that would let anyone with dashboard access replay the
     * sender's credentials — never persisted, even redacted-looking ones.
     */
    private const REDACTED_HEADERS = ['authorization', 'cookie', 'proxy-authorization'];

    public function __invoke(Request $request): Response
    {
        $webhookId = $request->header('WebHook-ID');
        $verified = $request->attributes->get('webhook_signature_error') === null;

        if ($webhookId !== null) {
            $existing = WebhookEvent::where('webhook_id', $webhookId)->first();
            if ($existing !== null) {
                return $this->response($existing->signature_verified);
            }
        }

        $payload = $request->json()->all();

        try {
            WebhookEvent::create([
                'webhook_id' => $webhookId,
                'event_type' => $payload['type'] ?? null,
                'source' => $payload['source'] ?? null,
                'subject' => $payload['subject'] ?? null,
                'payload' => $payload,
                'headers' => $this->redactHeaders($request->headers->all()),
                'received_at' => now(),
                'signature_verified' => $verified,
            ]);
        } catch (QueryException $e) {
            // Two concurrent deliveries with the same WebHook-ID can both pass
            // the exists-check above before either commits. The unique index
            // rejects the loser; fall back to whatever outcome actually won,
            // rather than surfacing a 500 for what is really a duplicate.
            if ($webhookId !== null && $e->getCode() === '23000') {
                $existing = WebhookEvent::where('webhook_id', $webhookId)->first();

                return $this->response($existing?->signature_verified ?? $verified);
            }

            throw $e;
        }

        return $this->response($verified);
    }

    private function redactHeaders(array $headers): array
    {
        foreach (self::REDACTED_HEADERS as $name) {
            if (isset($headers[$name])) {
                $headers[$name] = ['[redacted]'];
            }
        }

        return $headers;
    }

    private function response(bool $verified): Response
    {
        if (! $verified) {
            // Keep verification detail (JWKS URL, missing key id, etc.) out of
            // the response body — it's logged by VerifyWebhookSignature instead.
            return response()->json(['error' => 'Webhook verification failed'], 401);
        }

        return response('', 204);
    }
}
