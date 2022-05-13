<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Event;

use Illuminate\Foundation\Events\Dispatchable;

final class UserAuthorizedEvent
{
    use Dispatchable;

    public function __construct(
        private readonly string $uuid,
        private readonly string $name,
        private readonly string $email,
    ) {
    }

    public function getUuid(): string
    {
        return $this->uuid;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getEmail(): string
    {
        return $this->email;
    }
}
