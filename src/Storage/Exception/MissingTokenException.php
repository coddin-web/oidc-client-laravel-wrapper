<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Storage\Exception;

final class MissingTokenException extends \Exception
{
    public static function make(): self
    {
        return new self('Stored token is not of instance `Lcobucci\JWT\Token`');
    }
}
