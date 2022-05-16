<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Helper;

use Illuminate\Contracts\Config\Repository;

final class ConfigRepository
{
    public function __construct(
        private readonly Repository $configRepository,
    ) {
    }

    /**
     * @throws ConfigRepositoryException
     */
    public function getAsString(string $key): string
    {
        $value = $this->configRepository->get($key);

        if (!is_string($value)) {
            throw ConfigRepositoryException::notAString();
        }

        return $value;
    }

    /**
     * @throws ConfigRepositoryException
     */
    public function getAsBool(string $key): bool
    {
        $value = $this->configRepository->get($key);

        if (!is_bool($value)) {
            throw ConfigRepositoryException::notABool();
        }

        return $value;
    }

    /**
     * @return array<mixed, mixed>
     * @throws ConfigRepositoryException
     */
    public function getAsArray(string $key): array
    {
        $value = $this->configRepository->get($key);

        if (!is_array($value)) {
            throw ConfigRepositoryException::notAnArray();
        }

        return $value;
    }
}
