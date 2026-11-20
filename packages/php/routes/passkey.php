<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Jw1980\Passkey\Laravel\Http\HandoffController;
use Jw1980\Passkey\Laravel\Http\PasskeyController;
use Jw1980\Passkey\Laravel\Http\WellKnownController;

$auth = (array) config('passkey.routes.auth_middleware');

Route::prefix((string) config('passkey.routes.prefix'))->middleware('throttle:passkey')->group(function () use ($auth): void {
    Route::middleware((array) config('passkey.routes.middleware'))->group(function () use ($auth): void {
        Route::post('login/options', [PasskeyController::class, 'loginOptions'])->name('passkey.login.options');
        Route::post('login/verify', [PasskeyController::class, 'loginVerify'])->name('passkey.login.verify');

        Route::middleware($auth)->group(function (): void {
            Route::post('register/options', [PasskeyController::class, 'registerOptions'])->name('passkey.register.options');
            Route::post('register/verify', [PasskeyController::class, 'registerVerify'])->name('passkey.register.verify');
            Route::get('passkeys', [PasskeyController::class, 'index'])->name('passkey.index');
            Route::patch('passkeys/{passkey}', [PasskeyController::class, 'update'])->name('passkey.update');
            Route::delete('passkeys/{passkey}', [PasskeyController::class, 'destroy'])->name('passkey.destroy');

            if (config('passkey.handoff.enabled') === true) {
                Route::post('handoff/authorize', [HandoffController::class, 'authorize'])->name('passkey.handoff.authorize');
            }
        });
    });

    if (config('passkey.handoff.enabled') === true) {
        Route::post('handoff/exchange', [HandoffController::class, 'exchange'])
            ->middleware((array) config('passkey.handoff.exchange_middleware'))
            ->name('passkey.handoff.exchange');
    }
});

if (config('passkey.android.package') !== null && config('passkey.android.fingerprints') !== []) {
    Route::get('.well-known/assetlinks.json', [WellKnownController::class, 'assetLinks'])->name('passkey.assetlinks');
}
if (config('passkey.apple.app_ids') !== []) {
    Route::get('.well-known/apple-app-site-association', [WellKnownController::class, 'appleAppSiteAssociation'])->name('passkey.apple');
}
