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
        'scopes' => [
            'profile',
            'email',
        ],
    ],
    'private_key' => [
        'base64' => env('OIDC_BASE64_PRIVATE_KEY'),
    ],
    'token_storage' => [
        'adaptor' => null,
    ],
    'curl' => [
        'verify_host' => env('OIDC_CURL_VERIFY_HOST', true),
        'verify_peer' => env('OIDC_CURL_VERIFY_PEER', true),
    ],
];
