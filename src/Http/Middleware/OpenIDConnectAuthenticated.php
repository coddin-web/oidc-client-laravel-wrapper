<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Builder\OpenIDConnectClientBuilder;
use Coddin\OpenIDConnectClient\Event\UserAuthorizedEvent;
use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Coddin\OpenIDConnectClient\Service\Token\Storage\TokenStorageAdaptor;
use Illuminate\Http\Request;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Support\Facades\Log;
use Jumbojett\OpenIDConnectClientException;
use Lcobucci\JWT\Token\Plain;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

final class OpenIDConnectAuthenticated
{
    public function __construct(
        private readonly ResponseFactory $responseFactory,
        private readonly OpenIDConnectClientBuilder $openIDConnectClientBuilder,
        private readonly JWTVerifierBuilder $jwtVerifierBuilder,
        private readonly TokenStorageAdaptor $tokenStorageAdaptor,
        private readonly ConfigRepository $configRepository,
    ) {
    }

    /**
     * @throws HttpException
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        $token = $this->tokenStorageAdaptor->find();

        if ($token !== null) {
            return $this->handleExistingToken($token, $request, $next);
        }

        try {
            $jwtVerifier = $this->jwtVerifierBuilder->execute();
            $openIDClient = $this->openIDConnectClientBuilder->execute();
            $openIDClient->authenticate();

            /** @var Plain $token */
            $token = $jwtVerifier->parser()->parse($openIDClient->getIdToken());
            $this->tokenStorageAdaptor->put(
                token: $token,
            );

            $userUuid = $token->claims()->get('sub');
            $userName = $token->claims()->get('name');
            $userEmail = $token->claims()->get('email');

            UserAuthorizedEvent::dispatch(
                $userUuid,
                $userName,
                $userEmail,
            );
        } catch (OpenIDConnectClientException $e) {
            Log::error('Authenticating the OpenIDConnect Client failed:');
            Log::error($e->getMessage(), $e->getTrace());

            throw new HttpException(Response::HTTP_UNAUTHORIZED);
        } catch (ConfigRepositoryException $e) {
            Log::error($e->getMessage(), $e->getTrace());

            throw new HttpException(Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Consume the code from the URL and redirect to the intended URL without
        // the query parameter still visible.
        $oauthCode = $request->get('code');
        if (is_string($oauthCode) && strlen($oauthCode) > 900) {
            return $this->responseFactory->redirectTo($request->getPathInfo());
        }

        return $next($request);
    }

    private function handleExistingToken(
        \Lcobucci\JWT\Token $token,
        Request $request,
        \Closure $next,
    ): mixed {
        try {
            $openIDClient = $this->openIDConnectClientBuilder->execute();
            $stillActiveResponse = $openIDClient->introspectToken(
                token: $token->toString(),
                clientSecret: $this->configRepository->getAsString('oidc.client.secret'),
            );
        } catch (ConfigRepositoryException | OpenIDConnectClientException $e) {
            throw new HttpException(Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        if (!is_object($stillActiveResponse)) {
            $this->tokenStorageAdaptor->forget();

            return $this->responseFactory->redirectTo($request->getPathInfo());
        }

        // This is a shortcoming of the library returning an unstructured object.
        /* @phpstan-ignore-next-line */
        if ($stillActiveResponse->active === true) {
            return $next($request);
        } else {
            $this->tokenStorageAdaptor->forget();

            return $this->responseFactory->redirectTo($request->getPathInfo());
        }
    }
}
