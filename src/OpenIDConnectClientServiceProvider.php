<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient;

use Coddin\OpenIDConnectClient\Http\Middleware\OpenIDConnectAuthenticated;
use Coddin\OpenIDConnectClient\Http\Middleware\TokenAuthenticated;
use Coddin\OpenIDConnectClient\Service\Token\Storage\IlluminateSessionAdaptorToken;
use Coddin\OpenIDConnectClient\Service\Token\Storage\TokenStorageAdaptor;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

/**
 * @codeCoverageIgnore
 */
final class OpenIDConnectClientServiceProvider extends ServiceProvider
{
    public function boot(Router $router): void
    {
        $this->publishes(paths: [
            __DIR__ . '/../config/oidc.php' => config_path('oidc.php'),
        ]);

        $router->middlewareGroup(
            name: 'oidc',
            middleware: [OpenIDConnectAuthenticated::class],
        );

        $router->middlewareGroup(
            name: 'oidc.api',
            middleware: [TokenAuthenticated::class],
        );

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }

    /**
     * @throws \Exception
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            path: __DIR__ . '/../config/oidc.php',
            key: 'oidc',
        );

        $configuredAdaptor = config('oidc.token_storage.adaptor');
        if (!is_string($configuredAdaptor) && $configuredAdaptor !== null) {
            throw new \Exception(
                'The configured token storage adaptor should be a FQN representation of the class you want to use',
            );
        }

        if (is_string($configuredAdaptor) && !class_exists($configuredAdaptor)) {
            throw new \Exception('The configure token storage adaptor class does not exist');
        }

        $this->app->bind(
            TokenStorageAdaptor::class,
            ($configuredAdaptor ?? IlluminateSessionAdaptorToken::class),
        );
    }
}
