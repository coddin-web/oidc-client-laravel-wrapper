<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Builder\Exception;

final class JWTVerifierBuilderException extends \Exception
{
    public static function invalidPrivateKeyPath(mixed $path): self
    {
        return new self(
            sprintf(
                'An invalid path was given to the jwtVerifierBuilder: %s',
                \strval($path),
            ),
        );
    }
}
