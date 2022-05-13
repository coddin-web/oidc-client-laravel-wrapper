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

    public function find(): ?Token
    {
        $token = $this->sessionStore->get($this->getStorageKey());
        if (!$token instanceof Token) {
            return null;
        }

        return $token;
    }

    public function get(): Token
    {
        $token = $this->find();

        if ($token === null) {
            throw MissingTokenException::make();
        }

        return $token;
    }

    public function put(Token $token): void
    {
        $this->sessionStore->put($this->getStorageKey(), $token);
    }

    public function forget(): void
    {
        $this->sessionStore->forget($this->getStorageKey());
    }

    public function getStorageKey(): string
    {
        return 'oidc_id_token';
    }
}
