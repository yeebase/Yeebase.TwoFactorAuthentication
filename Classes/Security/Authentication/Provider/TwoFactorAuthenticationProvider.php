<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Session\SessionManagerInterface;
use Neos\Utility\Exception\PropertyNotAccessibleException;
use Neos\Utility\ObjectAccess;
use Yeebase\TwoFactorAuthentication\Error\SecondFactorSetupException;
use Yeebase\TwoFactorAuthentication\Error\SecondFactorLoginException;
use Yeebase\TwoFactorAuthentication\Http\RedirectComponent;
use Yeebase\TwoFactorAuthentication\Http\RedirectMiddleware;
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
     * @throws AuthenticationRequiredException | UnsupportedAuthenticationTokenException | SecondFactorLoginException | SecondFactorSetupException
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
                throw new SecondFactorLoginException();
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
            throw new SecondFactorSetupException();
        } else {
            /** @noinspection PhpUnhandledExceptionInspection */
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
        }
    }
}
