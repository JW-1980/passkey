<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Jw1980\Passkey\Laravel\Http\WellKnownController;

if (config('passkey.android.package') !== null && config('passkey.android.fingerprints') !== []) {
    Route::get('.well-known/assetlinks.json', [WellKnownController::class, 'assetLinks'])->name('passkey.assetlinks');
}
if (config('passkey.apple.app_ids') !== []) {
    Route::get('.well-known/apple-app-site-association', [WellKnownController::class, 'appleAppSiteAssociation'])->name('passkey.apple');
}
if (config('passkey.relying_party.related_origins') !== []) {
    Route::get('.well-known/webauthn', [WellKnownController::class, 'relatedOrigins'])->name('passkey.related-origins');
}
