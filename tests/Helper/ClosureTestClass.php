<?php

declare(strict_types=1);

namespace Coddin\Tests\Helper;

class ClosureTestClass
{
    public function __invoke(mixed $value): mixed
    {
        return $value;
    }
}
