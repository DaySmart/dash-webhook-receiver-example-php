<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Livewire\EventFeed;
use App\Models\WebhookEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\Livewire;
use Tests\TestCase;

class EventFeedTest extends TestCase
{
    use RefreshDatabase;

    private function makeEvent(array $overrides = []): WebhookEvent
    {
        return WebhookEvent::create(array_merge([
            'webhook_id' => 'delivery-'.str()->random(8),
            'event_type' => 'customer.registered',
            'source' => 'https://api.daysmartrecreation.com/customers',
            'subject' => 'cust_1',
            'payload' => ['type' => 'customer.registered'],
            'headers' => ['Content-Type' => 'application/json'],
            'received_at' => now(),
            'signature_verified' => true,
        ], $overrides));
    }

    public function test_deleting_a_single_event_removes_only_that_row(): void
    {
        $keep = $this->makeEvent();
        $remove = $this->makeEvent();

        Livewire::test(EventFeed::class)
            ->call('delete', $remove->id)
            ->assertOk();

        $this->assertModelMissing($remove);
        $this->assertModelExists($keep);
    }

    public function test_clear_all_removes_every_event(): void
    {
        $this->makeEvent();
        $this->makeEvent();

        Livewire::test(EventFeed::class)
            ->call('clearAll')
            ->assertOk();

        $this->assertSame(0, WebhookEvent::count());
    }
}
