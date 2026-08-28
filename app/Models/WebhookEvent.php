<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class WebhookEvent extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $fillable = [
        'webhook_id',
        'event_type',
        'source',
        'subject',
        'payload',
        'headers',
        'received_at',
        'signature_verified',
    ];

    protected $casts = [
        'payload' => 'array',
        'headers' => 'array',
        'received_at' => 'datetime',
        'signature_verified' => 'boolean',
    ];
}
