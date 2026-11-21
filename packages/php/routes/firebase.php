<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Jw1980\Passkey\Laravel\Http\FirebaseHubController;

/*
 * The auth hub (Firebase mode). No session and no CSRF middleware: every signed-in route takes the
 * Firebase ID token as a bearer token, and the hub does its own CORS and rate limiting.
 */
Route::prefix((string) config('passkey.routes.prefix'))
    ->middleware((array) config('passkey.firebase.middleware'))
    ->group(function (): void {
        Route::match(['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'], '{route}', FirebaseHubController::class)
            ->where('route', '(login|register)/(options|verify)|handoff/(authorize|exchange)|passkeys(/[A-Za-z0-9_-]+)?')
            ->name('passkey.firebase');
    });

require __DIR__.'/well-known.php';
