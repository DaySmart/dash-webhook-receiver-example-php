<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Webhook Events</title>

    {{--
        Tailwind CSS — Play CDN for zero-build-step development use.
        cdn.tailwindcss.com is a *dynamic* script that generates CSS on the fly
        for the classes it detects; no stable SRI hash is possible for it.
        For a production deployment, replace this with a compiled Tailwind build:
        https://tailwindcss.com/docs/installation
    --}}
    <script src="https://cdn.tailwindcss.com"></script>

    {{-- Alpine.js is bundled with Livewire 3+ and auto-started via @livewireScripts below;
         loading it separately here causes duplicate Alpine instances and breaks x-data/x-show. --}}

    @livewireStyles
</head>
<body class="bg-gray-50 text-gray-900 antialiased">

<header class="bg-white border-b border-gray-200 px-6 py-4 flex items-center gap-3">
    <svg class="w-6 h-6 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round"
              d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m13.35-.622 1.757-1.757a4.5 4.5 0 0 0-6.364-6.364l-4.5 4.5a4.5 4.5 0 0 0 1.242 7.244" />
    </svg>
    <h1 class="text-lg font-semibold tracking-tight">Webhook Events</h1>
    <span class="ml-auto text-xs text-gray-400">Live feed — refreshes every 3 s</span>
</header>

<main class="max-w-7xl mx-auto px-4 py-6">
    {{ $slot }}
</main>

@livewireScripts
</body>
</html>
