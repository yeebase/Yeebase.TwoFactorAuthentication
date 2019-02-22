<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Security\Authentication\EntryPoint\WebRedirect;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Yeebase\TwoFactorAuthentication\Security\Authentication\Token\OtpToken;
use Yeebase\TwoFactorAuthentication\Service\TwoFactorAuthenticationService;

/**
 * An authentication provider that adds an additional layer of security by validating a 2FA token.
 */
final class TwoFactorAuthenticationProvider extends AbstractProvider
{

    /**
     * @Flow\Inject
     * @var Bootstrap
     */
    protected $bootstrap;

    /**
     * @Flow\Inject
     * @var SecurityContext
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var TwoFactorAuthenticationService
     */
    protected $twoFactorAuthenticationService;

    /**
     * @Flow\InjectConfiguration(path="routes.login")
     * @var array
     */
    protected $loginRouteValues;

    /**
     * @Flow\InjectConfiguration(path="routes.setup")
     * @var array
     */
    protected $setupRouteValue;

    /**
     * @Flow\InjectConfiguration(path="requireTwoFactorAuthentication")
     * @var bool
     */
    protected $requireTwoFactorAuthentication;

    public function getTokenClassNames(): array
    {
        return [OtpToken::class];
    }

    /**
     * @param TokenInterface $authenticationToken
     * @throws AuthenticationRequiredException | UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken): void
    {
        if (!$authenticationToken instanceof OtpToken) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1549978976);
        }
        $account = $this->securityContext->getAccount();
        if ($account === null) {
            throw new AuthenticationRequiredException('This provider can only authenticate if on top of a previously authenticated token', 1549979039);
        }
        if ($this->twoFactorAuthenticationService->isTwoFactorAuthenticationEnabledFor($account)) {
            if (!$authenticationToken->hasOtp()) {
                $this->redirectToLogin();
                return;
            }
            if ($this->twoFactorAuthenticationService->validateOtp($account, $authenticationToken->getOtp())) {
                /** @noinspection PhpUnhandledExceptionInspection */
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                $authenticationToken->setAccount($account);
            } else {
                /** @noinspection PhpUnhandledExceptionInspection */
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            }
            return;
        }
        if ($this->requireTwoFactorAuthentication) {
            $this->redirectToSetup();
        } else {
            /** @noinspection PhpUnhandledExceptionInspection */
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
        }
    }

    /**
     * Triggers a redirect to the 2FA login route configured at routes.login or throws an exception if the configuration is missing/incorrect
     */
    private function redirectToLogin(): void
    {
        try {
            $this->validateRouteValues($this->loginRouteValues);
        } catch (\InvalidArgumentException $exception) {
            throw new \RuntimeException('Missing/invalid routes.login configuration: ' . $exception->getMessage(), 1550660144, $exception);
        }
        $this->redirect($this->loginRouteValues);
    }

    /**
     * Triggers a redirect to the 2FA setup route configured at routes.setup or throws an exception if the configuration is missing/incorrect
     */
    private function redirectToSetup(): void
    {
        try {
            $this->validateRouteValues($this->setupRouteValue);
        } catch (\InvalidArgumentException $exception) {
            throw new \RuntimeException('Missing/invalid routes.setup configuration: ' . $exception->getMessage(), 1550660178, $exception);
        }
        $this->redirect($this->setupRouteValue);
    }

    private function validateRouteValues(array $routeValues): void
    {
        $requiredRouteValues = ['@package', '@controller', '@action'];
        foreach ($requiredRouteValues as $routeValue) {
            if (!array_key_exists($routeValue, $routeValues)) {
                throw new \InvalidArgumentException(sprintf('Missing "%s" route value', $routeValue), 1550660039);
            }
        }
    }

    private  function redirect(array $routeValues): void {
        $requestHandler = $this->bootstrap->getActiveRequestHandler();
        if (!$requestHandler instanceof HttpRequestHandlerInterface) {
            throw new \RuntimeException('This provider only supports HTTP requests', 1549985779);
        }
        $webRedirect = new WebRedirect();
        $webRedirect->setOptions(['routeValues' => $routeValues]);
        /** @noinspection PhpUnhandledExceptionInspection */
        $webRedirect->startAuthentication($requestHandler->getHttpRequest(), $requestHandler->getHttpResponse());
    }
}
