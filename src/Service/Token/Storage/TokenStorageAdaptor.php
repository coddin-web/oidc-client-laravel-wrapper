<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token\Storage;

use Coddin\OpenIDConnectClient\Service\Token\Storage\Exception\MissingTokenException;
use Lcobucci\JWT\Token;

interface TokenStorageAdaptor
{
    public function find(): ?Token;

    /**
     * @throws MissingTokenException
     */
    public function get(): Token;

    public function put(Token $token): void;

    public function forget(): void;

    public function getStorageKey(): string;
}
