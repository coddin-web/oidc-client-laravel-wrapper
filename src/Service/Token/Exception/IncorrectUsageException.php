<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token\Exception;

final class IncorrectUsageException extends \Exception
{
    public static function incorrectClaimsType(): self
    {
        return new self(
            'jumbojett/openid-connect-php returns mixed, but it should be an array, when it is not an array an incorrect method has been used',
        );
    }
}
