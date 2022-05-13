<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Service\Token;

final class Claims implements DataSetInterface
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        private readonly array $data,
    ) {
    }

    public function get(string $key): mixed
    {
        // phpcs:ignore Squiz.Formatting.OperatorBracket.MissingBrackets
        return $this->data[$key] ?? null;
    }

    public function has(string $key): bool
    {
        return \array_key_exists($key, $this->data);
    }
}
