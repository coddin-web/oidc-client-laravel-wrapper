<?php

declare(strict_types=1);

namespace Coddin\Tests\Unit\Helper;

use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

// phpcs:disable PSR1.Methods.CamelCapsMethodName
final class ConfigRepositoryTest extends TestCase
{
    /** @var Repository & MockObject */
    private Repository|MockObject $illuminateConfigRepository;

    protected function setUp(): void
    {
        $this->illuminateConfigRepository = $this->createMock(Repository::class);
    }

    /** @test */
    public function get_as_string_invalid(): void
    {
        $this->illuminateConfigRepository
            ->expects(self::once())
            ->method('get')
            ->with('key')
            ->willReturn([]);

        self::expectException(ConfigRepositoryException::class);
        self::expectExceptionMessage('The config value is not a string');

        $configRepository = new ConfigRepository(
            configRepository: $this->illuminateConfigRepository,
        );
        $configRepository->getAsString('key');
    }

    /** @test */
    public function get_as_string(): void
    {
        $this->illuminateConfigRepository
            ->expects(self::once())
            ->method('get')
            ->with('key')
            ->willReturn('this_is_a_value');

        $configRepository = new ConfigRepository(
            configRepository: $this->illuminateConfigRepository,
        );

        /** @noinspection PhpUnhandledExceptionInspection */
        $value = $configRepository->getAsString('key');

        self::assertEquals('this_is_a_value', $value);
    }

    /** @test */
    public function get_as_bool_invalid(): void
    {
        $this->illuminateConfigRepository
            ->expects(self::once())
            ->method('get')
            ->with('key')
            ->willReturn([]);

        self::expectException(ConfigRepositoryException::class);
        self::expectExceptionMessage('The config value is not a bool');

        $configRepository = new ConfigRepository(
            configRepository: $this->illuminateConfigRepository,
        );
        $configRepository->getAsBool('key');
    }

    /** @test */
    public function get_as_bool(): void
    {
        $this->illuminateConfigRepository
            ->expects(self::once())
            ->method('get')
            ->with('key')
            ->willReturn(true);

        $configRepository = new ConfigRepository(
            configRepository: $this->illuminateConfigRepository,
        );

        /** @noinspection PhpUnhandledExceptionInspection */
        $value = $configRepository->getAsBool('key');

        self::assertTrue($value);
    }
}
