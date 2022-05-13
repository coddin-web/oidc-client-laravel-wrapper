<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token;

interface DataSetInterface
{
    public function get(string $key): mixed;

    public function has(string $key): bool;
}
