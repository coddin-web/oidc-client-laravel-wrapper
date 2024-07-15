<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Builder\OpenIDConnectClientBuilder;
use Coddin\OpenIDConnectClient\Event\UserAuthorizedEvent;
use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Coddin\OpenIDConnectClient\Helper\DateTimeDiffCalculator;
use Coddin\OpenIDConnectClient\Service\Token\Storage\Exception\MissingTokenException;
use Coddin\OpenIDConnectClient\Service\Token\Storage\TokenStorageAdaptor;
use Illuminate\Http\Request;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Support\Facades\Auth;
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
     * @throws ConfigRepositoryException
     * @throws MissingTokenException
     * @throws OpenIDConnectClientException
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        if (\str_contains($request->getPathInfo(), 'logout')) {
            return $next($request);
        }

        $idToken = $this->tokenStorageAdaptor->find(TokenStorageAdaptor::ID_TOKEN_STORAGE_KEY);
        $accessToken = $this->tokenStorageAdaptor->find(TokenStorageAdaptor::ACCESS_TOKEN_STORAGE_KEY);

        if ($idToken !== null && $accessToken !== null) {
            return $this->handleExistingToken(
                accessToken: $accessToken,
                request: $request,
                next: $next,
            );
        }

        try {
            $jwtVerifier = $this->jwtVerifierBuilder->execute();
            $openIDClient = $this->openIDConnectClientBuilder->execute();

            // Dynamically set the redirect URL?
            $openIDClient->setRedirectURL($this->configRepository->getAsString('app.url') . $request->getPathInfo());

            $openIDClient->authenticate();

            $accessToken = $jwtVerifier->parser()->parse($openIDClient->getAccessToken());
            $idToken = $jwtVerifier->parser()->parse($openIDClient->getIdToken());
            $this->tokenStorageAdaptor->put(
                idToken: $idToken,
                accessToken: $accessToken,
                refreshToken: $openIDClient->getRefreshToken(),
            );

            /** @var Plain $idToken */
            $userUuid = $idToken->claims()->get('sub');
            $userName = $idToken->claims()->get('nickname');
            $userEmail = $idToken->claims()->get('email');

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
        if (is_string($oauthCode) && strlen($oauthCode) > 800) {
            return $this->responseFactory->redirectTo($request->getPathInfo());
        }

        return $next($request);
    }

    /**
     * @throws OpenIDConnectClientException
     * @throws MissingTokenException
     * @throws ConfigRepositoryException
     */
    private function handleExistingToken(
        \Lcobucci\JWT\Token $accessToken,
        Request $request,
        \Closure $next,
    ): mixed {
        if ($accessToken->isExpired(new \DateTimeImmutable())) {
            $this->tokenStorageAdaptor->forget();
            Auth::logout();

            return $this->responseFactory->redirectTo(
                $this->configRepository->getAsString('oidc.provider.logout_endpoint'),
            );
        }

        /** @var Plain $accessToken */
        $claims = $accessToken->claims();
        /** @var \DateTimeInterface $issuedAt */
        $issuedAt = $claims->get('iat');
        /** @var \DateTimeInterface $expiresAt */
        $expiresAt = $claims->get('exp');

        $validityInSeconds = DateTimeDiffCalculator::differenceInSeconds($issuedAt, $expiresAt);
        $secondsLeft = DateTimeDiffCalculator::differenceInSeconds(new \DateTimeImmutable(), $expiresAt);
        $percentageLeft = (($secondsLeft / $validityInSeconds) * 100);

        if ($percentageLeft <= 25) {
            $refreshToken = $this->tokenStorageAdaptor->get(TokenStorageAdaptor::REFRESH_TOKEN_STORAGE_KEY);
            $openIDClient = $this->openIDConnectClientBuilder->execute();
            $openIDClient->refreshToken($refreshToken->toString());

            $jwtVerifier = $this->jwtVerifierBuilder->execute();
            $newIdToken = $jwtVerifier->parser()->parse($openIDClient->getIdToken());
            $newAccessToken = $jwtVerifier->parser()->parse($openIDClient->getAccessToken());

            $this->tokenStorageAdaptor->put(
                idToken: $newIdToken,
                accessToken: $newAccessToken,
                refreshToken: $openIDClient->getRefreshToken(),
            );
        }

        return $next($request);
    }
}
