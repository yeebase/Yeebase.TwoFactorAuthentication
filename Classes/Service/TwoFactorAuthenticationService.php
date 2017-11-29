<?php
namespace Yeebase\TwoFactorAuthentication\Service;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Account;
use PragmaRX\Google2FA\Google2FA;
use Yeebase\TwoFactorAuthentication\Domain\Dto\TwoFactorAuthenticationCredentialsSource;

/**
 * @Flow\Scope("singleton")
 */
class TwoFactorAuthenticationService
{

    /**
     * @var PersistenceManagerInterface
     * @Flow\Inject
     */
    protected $persistenceManager;

    /**
     * @var string
     * @Flow\InjectConfiguration("applicationName")
     */
    protected $applicationName;

    public function getPasswordCredentialsSource(Account $account): string
    {
        if ($this->hasTwoFactorAuthenticationCredentials($account)) {
            return $this->getTwoFactorAuthenticationCredentials($account)->credentialsSource;
        } else {
            return $account->getCredentialsSource();
        }
    }

    public function validateSecret(string $secret, Account $account, bool $isInitialValidation = false): bool
    {
        $secretIsValid = false;
        $credentials = $this->getTwoFactorAuthenticationCredentials($account);
        $userSecret = $isInitialValidation ? $credentials->pendingSecret : $credentials->secret;

        try {
            $secretIsValid = (new Google2Fa())->verifyKey($userSecret, $secret);
        } catch (\Exception $e) {
            // nothing to do here if validation fails
        }

        return $secretIsValid;
    }

    public function hasTwoFactorAuthenticationEnabled(Account $account): bool
    {
        return $this->hasTwoFactorAuthenticationCredentials($account) && $this->getTwoFactorAuthenticationCredentials($account)->enabled;
    }

    public function enableTwoFactorAuthentication(Account $account)
    {
        $existingCredentials = $this->getTwoFactorAuthenticationCredentials($account);
        $updatedCredentials = new TwoFactorAuthenticationCredentialsSource(
            $existingCredentials->credentialsSource,
            true,
            $existingCredentials->pendingSecret,
            ''
        );

        $this->setTwoFactorAuthenticationCredentials($account, $updatedCredentials);
        $this->persistenceManager->update($account);
    }

    public function disableTwoFactorAuthentication(Account $account)
    {
        $existingCredentials = $this->getTwoFactorAuthenticationCredentials($account);
        $updatedCredentials = new TwoFactorAuthenticationCredentialsSource(
            $existingCredentials->credentialsSource,
            false,
            '',
            ''
        );

        $this->setTwoFactorAuthenticationCredentials($account, $updatedCredentials);
        $this->persistenceManager->update($account);
    }

    public function createActivationQrCode(Account $account): string
    {
        $this->setupTwoFactorAuthenticationCredentials($account);
        $google2fa = new Google2Fa();

        $existingCredentials = $this->getTwoFactorAuthenticationCredentials($account);
        $secret = $existingCredentials->pendingSecret ?: $google2fa->generateSecretKey();

        $updatedCredentials = new TwoFactorAuthenticationCredentialsSource(
            $existingCredentials->credentialsSource,
            false,
            '',
            $secret
        );

        $qrCodeUrl = $google2fa->getQRCodeGoogleUrl($this->applicationName, $account->getAccountIdentifier(), $secret);

        $this->setTwoFactorAuthenticationCredentials($account, $updatedCredentials);
        $this->persistenceManager->whitelistObject($account);
        $this->persistenceManager->update($account);

        return $qrCodeUrl;
    }

    protected function setupTwoFactorAuthenticationCredentials(Account $account)
    {
        if ($this->hasTwoFactorAuthenticationCredentials($account)) {
            return;
        }

        $credentials = new TwoFactorAuthenticationCredentialsSource($account->getCredentialsSource(), false, '', '');
        $this->setTwoFactorAuthenticationCredentials($account, $credentials);
    }

    protected function getTwoFactorAuthenticationCredentials(Account $account)
    {
        if (! $this->hasTwoFactorAuthenticationCredentials($account)) {
            throw new \Exception('Trying to access uninitialized Two-Factor-Authentication credentials.', 1511271518);
        }

        return TwoFactorAuthenticationCredentialsSource::fromJsonString($account->getCredentialsSource());
    }

    protected function setTwoFactorAuthenticationCredentials(Account $account, TwoFactorAuthenticationCredentialsSource $credentials)
    {
        $account->setCredentialsSource($credentials->toJsonString());
    }

    protected function hasTwoFactorAuthenticationCredentials(Account $account): bool
    {
        $credentials = $account->getCredentialsSource();

        return is_string($credentials)
        && is_array(json_decode($credentials, true))
        && (json_last_error() == JSON_ERROR_NONE) ? true : false;
    }
}
