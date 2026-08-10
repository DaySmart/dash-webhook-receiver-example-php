<?php

declare(strict_types=1);

namespace App\Livewire;

use App\Models\WebhookEvent;
use Illuminate\Contracts\View\View;
use Livewire\Attributes\Layout;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;

#[Layout('layouts.app')]
class EventFeed extends Component
{
    use WithPagination;

    #[Url]
    public string $search = '';

    public function updatingSearch(): void
    {
        $this->resetPage();
    }

    public function delete(string $id): void
    {
        WebhookEvent::whereKey($id)->delete();
    }

    public function clearAll(): void
    {
        WebhookEvent::query()->delete();
        $this->resetPage();
    }

    public function render(): View
    {
        $events = WebhookEvent::query()
            ->latest('received_at')
            ->when(
                $this->search !== '',
                fn ($q) => $q->where('event_type', 'like', "%{$this->search}%")
            )
            ->paginate(25);

        return view('livewire.event-feed', compact('events'));
    }
}
