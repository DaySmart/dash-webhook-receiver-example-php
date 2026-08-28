<?php

declare(strict_types=1);

namespace App\Exceptions;

use RuntimeException;

/**
 * Thrown when the sender's JWKS endpoint can't be reached or returns garbage
 * — as opposed to WebhookVerificationException, which means "we reached the
 * JWKS and the signature is genuinely invalid".
 *
 * Deliberately does NOT extend WebhookVerificationException: VerifyWebhookSignature
 * only catches that type, so this propagates to Laravel's default exception
 * handler and becomes a 500. Dash retries 5xx/timeout deliveries with
 * backoff, whereas a 401 here would be marked Abandoned and never retried —
 * permanently dropping the delivery over what's usually a transient outage.
 */
class JwksUnavailableException extends RuntimeException {}
