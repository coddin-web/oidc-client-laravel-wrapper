<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token\Storage;

use Coddin\OpenIDConnectClient\Service\Token\Storage\Exception\MissingTokenException;
use Lcobucci\JWT\Token;

interface TokenStorageAdaptor
{
    public const ACCESS_TOKEN_STORAGE_KEY = 'oidc_session_key_access_token';
    public const REFRESH_TOKEN_STORAGE_KEY = 'oidc_session_key_refresh_token';

    public function find(string $type): ?Token;

    /**
     * @throws MissingTokenException
     */
    public function get(string $type): Token;

    public function put(
        Token $accessToken,
        ?string $refreshToken = null,
    ): void;

    public function forget(): void;


    public function getAccessTokenStorageKey(): string;

    public function getRefreshTokenStorageKey(): string;
}
