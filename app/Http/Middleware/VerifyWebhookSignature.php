<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Exceptions\WebhookVerificationException;
use App\Services\WebhookSignatureVerifier;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

readonly class VerifyWebhookSignature
{
    public function __construct(private WebhookSignatureVerifier $verifier) {}

    public function handle(Request $request, Closure $next): Response
    {
        try {
            $this->verifier->verify($request);
        } catch (WebhookVerificationException $e) {
            Log::warning('Webhook signature verification failed', [
                'reason' => $e->getMessage(),
                'webhook_id' => $request->header('WebHook-ID'),
                'ip' => $request->ip(),
                'path' => $request->getPathInfo(),
            ]);

            // Deliveries that fail verification still get passed through to the
            // controller so they're persisted (with signature_verified = false)
            // for audit visibility, rather than vanishing silently on rejection.
            $request->attributes->set('webhook_signature_error', $e->getMessage());
        }

        return $next($request);
    }
}
