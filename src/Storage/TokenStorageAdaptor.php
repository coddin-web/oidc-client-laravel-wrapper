<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Storage;

use Coddin\OpenIDConnectClient\Storage\Exception\MissingTokenException;
use Lcobucci\JWT\Token as TokenInterface;

interface TokenStorageAdaptor
{
    /**
     * @throws MissingTokenException
     */
    public function get(): TokenInterface;

    public function put(TokenInterface $token): void;

    public function forget(): void;

    public function getStorageKey(): string;
}
