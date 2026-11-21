<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Http;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Jw1980\Passkey\Firebase\Http\AuthHub;
use Jw1980\Passkey\Firebase\Http\HubRequest;

/** Hands the hub's routes to the framework-neutral {@see AuthHub}. */
final class FirebaseHubController
{
    public function __invoke(Request $request, AuthHub $hub): Response
    {
        $headers = [];
        foreach ($request->headers->all() as $name => $values) {
            $headers[(string) $name] = (string) ($values[0] ?? '');
        }
        $answer = $hub->handle(new HubRequest(
            strtoupper($request->getMethod()),
            '/'.ltrim($request->path(), '/'),
            $headers,
            (string) $request->getContent(),
            (string) $request->ip(),
        ));
        if ($answer === null) {
            abort(404);
        }

        return new Response($answer->body, $answer->status, $answer->headers);
    }
}
