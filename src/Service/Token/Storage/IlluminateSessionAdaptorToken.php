<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token\Storage;

use Coddin\OpenIDConnectClient\Service\Token\Storage\Exception\MissingTokenException;
use Illuminate\Session\Store;
use Lcobucci\JWT\Token;

final class IlluminateSessionAdaptorToken implements TokenStorageAdaptor
{
    public function __construct(
        private readonly Store $sessionStore,
    ) {
    }

    public function find(string $type): ?Token
    {
        $token = $this->sessionStore->get($type);
        if (!$token instanceof Token) {
            return null;
        }

        return $token;
    }

    public function get(string $type): Token
    {
        $token = $this->find($type);

        if ($token === null) {
            throw MissingTokenException::make();
        }

        return $token;
    }

    public function put(
        Token $accessToken,
        ?string $refreshToken = null,
    ): void {
        $this->sessionStore->put($this->getAccessTokenStorageKey(), $accessToken);
        if ($refreshToken !== null) {
            $this->sessionStore->put($this->getRefreshTokenStorageKey(), $refreshToken);
        }
    }

    public function forget(): void
    {
        $this->sessionStore->forget($this->getAccessTokenStorageKey());
        $this->sessionStore->forget($this->getRefreshTokenStorageKey());
        $this->sessionStore->save();
    }

    public function getAccessTokenStorageKey(): string
    {
        return self::ACCESS_TOKEN_STORAGE_KEY;
    }

    public function getRefreshTokenStorageKey(): string
    {
        return self::REFRESH_TOKEN_STORAGE_KEY;
    }
}
