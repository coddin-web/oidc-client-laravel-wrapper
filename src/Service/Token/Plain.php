<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token;

use Coddin\OpenIDConnectClient\Service\TokenInterface;

final class Plain implements TokenInterface
{
    public function __construct(
        private readonly Claims $claims,
        private readonly string $encoded,
    ) {
    }

    public function getClaim(string $claim): mixed
    {
        return $this->claims->get($claim);
    }

    public function isExpired(\DateTimeInterface $now): bool
    {
        if (! $this->claims->has(ExistingClaims::EXPIRATION_TIME)) {
            return false;
        }

        return $now >= $this->claims->get(ExistingClaims::EXPIRATION_TIME);
    }

    public function toString(): string
    {
        return $this->encoded;
    }
}
