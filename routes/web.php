<?php

use App\Http\Controllers\WebhookController;
use App\Http\Controllers\WebhookHandshakeController;
use App\Http\Middleware\VerifyWebhookSignature;
use App\Livewire\EventFeed;
use Illuminate\Support\Facades\Route;

// Validation handshake — the sender performs this OPTIONS request once when a
// subscription is created to verify the endpoint is willing to accept deliveries.
Route::options('/webhooks', WebhookHandshakeController::class);

// Webhook delivery endpoint — protected by the RFC 9421 signature verifier.
Route::post('/webhooks', WebhookController::class)
    ->middleware(VerifyWebhookSignature::class);

// Live event dashboard
Route::get('/', EventFeed::class);
