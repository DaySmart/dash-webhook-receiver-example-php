<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('webhook_events', function (Blueprint $table) {
            $table->uuid('id')->primary();

            // WebHook-ID header — the sender's idempotency key.
            // Retried deliveries reuse the same ID; the unique index prevents duplicates.
            // Nullable because a delivery that fails signature verification may be
            // missing this header entirely (still stored as-is for audit).
            $table->string('webhook_id')->nullable()->unique();

            // CloudEvents v1.0 envelope fields. Nullable because a delivery
            // that fails signature verification is stored as-is for audit —
            // its payload may be malformed or missing fields entirely.
            $table->string('event_type')->nullable(); // e.g. "customer.registered"
            $table->string('source')->nullable();     // e.g. "https://api.daysmart.com/customers"
            $table->string('subject')->nullable();     // optional resource path

            // Full CloudEvents envelope as received
            $table->json('payload');

            // All request headers from the delivery (useful for debugging)
            $table->json('headers');

            $table->timestamp('received_at');

            // False when VerifyWebhookSignature flagged the delivery as failing
            // signature verification — such deliveries are still stored (and
            // rejected with a 401) so failures remain visible for audit.
            $table->boolean('signature_verified')->default(false);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('webhook_events');
    }
};
