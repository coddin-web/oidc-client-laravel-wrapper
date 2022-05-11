<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Helper;

final class ConfigRepositoryException extends \Exception
{
    public static function notAString(): self
    {
        return new self('The config value is not a string');
    }

    public static function notABool(): self
    {
        return new self('The config value is not a bool');
    }
}
