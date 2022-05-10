<?php

return [
    'provider' => [
        'endpoint' => env('OIDC_PROVIDER'),
        'issuer' => env('OIDC_ISSUER', env('OIDC_PROVIDER')),
    ],
    'client' => [
        'id' => env('OIDC_CLIENT_ID'),
        'secret' => env('OIDC_CLIENT_SECRET'),
        'use_pkce' => false,
        'redirect_url' => '/',
    ],
    'cert' => [
        'path' => env('OIDC_CERT_PATH'),
    ],
    'token_storage' => [
        'adaptor' => null,
    ],
];
