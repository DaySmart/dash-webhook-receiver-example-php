<div wire:poll.3s>

    {{-- Search --}}
    <div class="mb-4 flex items-center justify-between gap-4">
        <input
            wire:model.live.debounce.300ms="search"
            type="text"
            placeholder="Filter by event type…"
            class="w-full max-w-sm rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm
                   focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
        >

        @if ($events->isNotEmpty())
            <button
                wire:click="clearAll"
                wire:confirm="Delete all webhook events? This cannot be undone."
                class="shrink-0 rounded-md border border-red-200 px-3 py-2 text-xs font-medium text-red-600
                       hover:bg-red-50 transition-colors"
            >
                Clear all
            </button>
        @endif
    </div>

    @if ($events->isEmpty())
        <div class="rounded-lg border border-dashed border-gray-300 bg-white py-16 text-center text-gray-400">
            <p class="text-sm">No webhook events received yet.</p>
            <p class="mt-1 text-xs">Point your sender at <code class="font-mono bg-gray-100 px-1 rounded">POST /webhooks</code> to get started.</p>
        </div>
    @else
        <div class="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
            <table class="min-w-full divide-y divide-gray-200 text-sm">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider text-xs">Received</th>
                        <th class="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider text-xs">Event type</th>
                        <th class="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider text-xs">Source</th>
                        <th class="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider text-xs">Subject</th>
                        <th class="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider text-xs">WebHook-ID</th>
                        <th class="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider text-xs">Sig</th>
                        <th class="px-4 py-3"></th>
                    </tr>
                </thead>
                @foreach ($events as $event)
                    <tbody wire:key="event-{{ $event->id }}" x-data="{ open: false }" class="divide-y divide-gray-100">
                        <tr class="hover:bg-gray-50 transition-colors">
                            <td class="px-4 py-3 whitespace-nowrap text-gray-500 text-xs"
                                title="{{ $event->received_at->toIso8601String() }}">
                                {{ $event->received_at->diffForHumans() }}
                            </td>
                            <td class="px-4 py-3 whitespace-nowrap font-mono text-indigo-700 text-xs font-medium">
                                {{ $event->event_type }}
                            </td>
                            <td class="px-4 py-3 text-gray-600 text-xs max-w-xs truncate"
                                title="{{ $event->source }}">
                                {{ $event->source }}
                            </td>
                            <td class="px-4 py-3 text-gray-600 text-xs">
                                {{ $event->subject ?? '—' }}
                            </td>
                            <td class="px-4 py-3 font-mono text-gray-400 text-xs"
                                title="{{ $event->webhook_id }}">
                                {{ substr($event->webhook_id, 0, 8) }}…
                            </td>
                            <td class="px-4 py-3">
                                @if ($event->signature_verified)
                                    <span class="inline-flex items-center gap-1 rounded-full bg-green-50 px-2 py-0.5 text-xs font-medium text-green-700 ring-1 ring-green-600/20">
                                        ✓ verified
                                    </span>
                                @else
                                    <span class="inline-flex items-center rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-600/20">
                                        ✗ failed
                                    </span>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-right whitespace-nowrap">
                                <button @click="open = !open"
                                        class="text-xs text-indigo-600 hover:text-indigo-800 font-medium">
                                    <span x-text="open ? 'Hide' : 'Expand'"></span>
                                </button>
                                <button
                                    wire:click="delete('{{ $event->id }}')"
                                    wire:confirm="Delete this webhook event?"
                                    class="ml-3 text-xs text-red-500 hover:text-red-700 font-medium"
                                >
                                    Delete
                                </button>
                            </td>
                        </tr>

                        {{-- Expanded detail row --}}
                        <tr x-show="open" class="bg-gray-50">
                            <td colspan="7" class="px-4 py-4">
                                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                    <div>
                                        <p class="text-xs font-semibold text-gray-500 uppercase mb-2">Payload</p>
                                        <pre class="rounded bg-gray-900 text-green-300 text-xs p-4 overflow-auto max-h-96">{{ json_encode($event->payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
                                    </div>
                                    <div>
                                        <p class="text-xs font-semibold text-gray-500 uppercase mb-2">Headers</p>
                                        <pre class="rounded bg-gray-900 text-blue-300 text-xs p-4 overflow-auto max-h-96">{{ json_encode($event->headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                @endforeach
            </table>
        </div>

        <div class="mt-4">
            {{ $events->links() }}
        </div>
    @endif

</div>
