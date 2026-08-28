<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // No seed data — this app has no models worth seeding beyond
        // WebhookEvent rows, which only ever come from real deliveries.
    }
}
