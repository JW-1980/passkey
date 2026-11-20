<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        return config('passkey.connection');
    }

    public function up(): void
    {
        Schema::connection($this->getConnection())->create(config('passkey.tables.passkeys'), function (Blueprint $table): void {
            // SHA-256 of the credential ID: the ID itself can be longer than an index allows.
            $table->char('credential_hash', 64)->primary();
            $table->text('credential_id');
            $table->string('user_id', 191)->index();
            $table->string('user_handle', 86);
            $table->text('public_key');
            $table->unsignedBigInteger('counter')->default(0);
            $table->string('transports', 255);
            $table->char('aaguid', 36);
            $table->boolean('backup_eligible')->default(false);
            $table->boolean('backed_up')->default(false);
            $table->string('attestation_type', 32);
            $table->string('name', 100);
            $table->dateTime('created_at');
            $table->dateTime('last_used_at')->nullable();
        });

        Schema::connection($this->getConnection())->create(config('passkey.tables.challenges'), function (Blueprint $table): void {
            $table->char('key_hash', 64)->primary();
            $table->text('payload');
            $table->bigInteger('expires_at')->index();
        });
    }

    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(config('passkey.tables.challenges'));
        Schema::connection($this->getConnection())->dropIfExists(config('passkey.tables.passkeys'));
    }
};
