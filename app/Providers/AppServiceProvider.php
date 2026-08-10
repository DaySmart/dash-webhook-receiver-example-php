<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\JwksCache;
use App\Services\WebhookSignatureVerifier;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(JwksCache::class);
        $this->app->singleton(WebhookSignatureVerifier::class);
    }

    public function boot(): void {}
}
