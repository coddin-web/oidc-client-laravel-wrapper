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
    'private_key' => [
        'base64' => env('OIDC_BASE64_PRIVATE_KEY'),
    ],
    'token_storage' => [
        'adaptor' => null,
    ],
];
