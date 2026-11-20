<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Http;

use Illuminate\Http\JsonResponse;
use Jw1980\Passkey\WellKnown;

final class WellKnownController
{
    public function assetLinks(): JsonResponse
    {
        return new JsonResponse(WellKnown::assetLinks(
            (string) config('passkey.android.package'),
            array_values((array) config('passkey.android.fingerprints')),
        ));
    }

    public function appleAppSiteAssociation(): JsonResponse
    {
        return new JsonResponse(WellKnown::appleAppSiteAssociation(array_values((array) config('passkey.apple.app_ids'))));
    }
}
