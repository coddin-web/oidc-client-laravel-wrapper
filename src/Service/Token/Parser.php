<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token;

use Coddin\OpenIDConnectClient\Service\Token\Exception\IncorrectUsageException;

/**
 * A Parser for the jumbojett/openid-connect-php library.
 */
final class Parser
{
    /**
     * @throws IncorrectUsageException
     */
    public function parse(
        string $encodedToken,
        mixed $claims,
    ): Plain {
        if (!is_array($claims)) {
            throw IncorrectUsageException::incorrectClaimsType();
        }

        return new Plain(
            claims: new Claims($claims),
            encoded: $encodedToken,
        );
    }
}
