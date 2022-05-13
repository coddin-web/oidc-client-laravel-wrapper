<?php

namespace Coddin\OpenIDConnectClient\Service;

interface TokenInterface
{
    public function getClaim(string $claim): mixed;

    public function isExpired(\DateTimeInterface $now): bool;

    public function toString(): string;
}
