<?php
namespace Yeebase\TwoFactorAuthentication\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\EntryPoint\WebRedirect;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Yeebase\TwoFactorAuthentication\Security\Authentication\Token\TwoFactorUsernamePasswordToken;
use Yeebase\TwoFactorAuthentication\Service\TwoFactorAuthenticationService;

/**
 * An authentication provider that adds an additional layer of security by validating a Two-Factor-Authentication token.
 */
class TwoFactorAuthenticationProvider extends AbstractProvider
{
    /**
     * @var TwoFactorAuthenticationService
     * @Flow\Inject
     */
    protected $twoFactorAuthenticationService;

    /**
     * @var AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @var Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var HashService
     * @Flow\Inject
     */
    protected $hashService;

    /**
     * @var PersistenceManagerInterface
     * @Flow\Inject
     */
    protected $persistenceManager;

    /**
     * @var Bootstrap
     * @Flow\Inject
     */
    protected $bootstrap;

    /**
     * @var array
     * @Flow\InjectConfiguration("authenticationEntryPoint")
     */
    protected $entryPointConfiguration;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return [TwoFactorUsernamePasswordToken::class];
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (! in_array(get_class($authenticationToken), $this->getTokenClassNames())) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
        }

        $alreadyAuthenticated = false;
        if ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
        } else {
            $alreadyAuthenticated = true;
        }

        // Username-Password-Authentication

        $credentials = $authenticationToken->getCredentials();
        if (!is_array($credentials) || !isset($credentials[TwoFactorUsernamePasswordToken::CREDENTIALS_USERNAME]) || !isset($credentials[TwoFactorUsernamePasswordToken::CREDENTIALS_PASSWORD])) {
            // no username/password credentials given -> authentication failed
            return;
        }

        $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);

        $account = $this->retrieveAccountForToken($authenticationToken);
        $givenPassword = $credentials[TwoFactorUsernamePasswordToken::CREDENTIALS_PASSWORD];

        if ($account === null) {
            // account for username not found -> authentication failed
            $this->hashService->validatePassword($givenPassword, 'bcrypt=>$2a$14$DummySaltToPreventTim,.ingAttacksOnThisProvider');
            return;
        }

        $existingPasswordHash = $this->twoFactorAuthenticationService->getPasswordCredentialsSource($account);
        if (! $this->hashService->validatePassword($givenPassword, $existingPasswordHash)) {
            // invalid password for given username -> authentication failed
            $account->authenticationAttempted(TokenInterface::WRONG_CREDENTIALS);
            $this->accountRepository->update($account);
            $this->persistenceManager->whitelistObject($account);
            return;
        }

        if (! $this->twoFactorAuthenticationService->hasTwoFactorAuthenticationEnabled($account) || $alreadyAuthenticated) {
            // Two-Factor-Authentication is disabled or has been completed already -> authentication succeeded
            $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
            $this->accountRepository->update($account);
            $this->persistenceManager->whitelistObject($account);
            return;
        }

        // Authentication of Two-Factor-Authentication secret

        $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);

        $twoFactorSecret = $authenticationToken->getCredentials()[TwoFactorUsernamePasswordToken::CREDENTIALS_TWO_FACTOR_SECRET];
        if (empty($twoFactorSecret)) {
            // No secret given yet -> forward to insertSecret action
            $this->configureRedirectToInsertSecretAction();
            return;
        }

        $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);

        if ($this->twoFactorAuthenticationService->validateSecret($twoFactorSecret, $account)) {
            // Secret evaluated correctly -> authentication succeeded
            $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
        } else {
            // Invalid secret -> authentication failed
            $account->authenticationAttempted(TokenInterface::WRONG_CREDENTIALS);
        }
        $this->accountRepository->update($account);
        $this->persistenceManager->whitelistObject($account);
    }

    protected function retrieveAccountForToken(TokenInterface $authenticationToken): ?Account
    {
        $account = null;

        $username = $authenticationToken->getCredentials()[TwoFactorUsernamePasswordToken::CREDENTIALS_USERNAME];
        $providerName = $this->name;
        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function () use ($username, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($username, $providerName);
        });

        return $account;
    }

    protected function configureRedirectToInsertSecretAction()
    {
        /* @var HttpRequestHandlerInterface $requestHandler */
        $requestHandler = $this->bootstrap->getActiveRequestHandler();
        $request = $requestHandler->getHttpRequest();
        $response = $requestHandler->getHttpResponse();

        $webRedirect = new WebRedirect();
        $webRedirect->setOptions(['routeValues' => [
            '@package' => $this->entryPointConfiguration['package'],
            '@controller' => $this->entryPointConfiguration['controller'],
            '@action' => $this->entryPointConfiguration['action'],
            '@format' => 'html'
        ]]);

        $webRedirect->startAuthentication($request, $response);
    }
}
