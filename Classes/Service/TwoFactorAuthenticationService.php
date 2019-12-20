<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Service;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DBALException;
use Doctrine\DBAL\Exception\InvalidArgumentException;
use Doctrine\ORM\EntityManagerInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException;
use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;
use PragmaRX\Google2FA\Google2FA;
use Yeebase\TwoFactorAuthentication\Domain\ValueObjects\OneTimePassword;
use Yeebase\TwoFactorAuthentication\Domain\ValueObjects\ActivationQrCode;
use Yeebase\TwoFactorAuthentication\Domain\ValueObjects\Secret;
use Yeebase\TwoFactorAuthentication\Exception\InvalidOtpException;

/**
 * @Flow\Scope("singleton")
 */
final class TwoFactorAuthenticationService
{
    private const SECRETS_TABLE_NAME = 'yeebase_twofactorauthentication_secret';

    /**
     * @Flow\InjectConfiguration("applicationName")
     * @var string
     */
    protected $applicationName;

    /**
     * @Flow\InjectConfiguration("secretKeyLength")
     * @var int
     */
    protected $secretKeyLength;

    /**
     * @var Connection
     */
    private $dbal;

    /**
     * @var Google2FA
     */
    private $google2FA;

    public function initializeObject(): void
    {
        $this->google2FA = new Google2FA();
    }

    public function injectEntityManager(EntityManagerInterface $entityManager): void
    {
        $this->dbal = $entityManager->getConnection();
    }

    /**
     * Validate the given $otp and returns TRUE if it is valid for the specified $account
     */
    public function validateOtp(Account $account, OneTimePassword $otp): bool
    {
        try {
            $secretData = $this->dbal->fetchAssoc('SELECT secret, timestamp FROM ' . self::SECRETS_TABLE_NAME . ' WHERE accountIdentifier = :accountIdentifier AND authenticationProviderName = :authenticationProviderName LIMIT 1', [
                'accountIdentifier' => $account->getAccountIdentifier(),
                'authenticationProviderName' => $account->getAuthenticationProviderName(),
            ]);
        } catch (DBALException $exception) {
            throw new \RuntimeException('Failed to fetch secret from database, maybe a migration was not executed?', 1550662767, $exception);
        }
        if ($secretData === false) {
            return false;
        }

        try {
            $newTimestamp = $this->google2FA->verifyKeyNewer($secretData['secret'], $otp->toString(), (int)$secretData['timestamp']);
        } catch (IncompatibleWithGoogleAuthenticatorException | InvalidCharactersException | SecretKeyTooShortException $exception) {
            throw new \RuntimeException('Failed to verify secret/otp', 1550662882, $exception);
        }
        if ($newTimestamp === false) {
            return false;
        }
        try {
            $this->dbal->update(self::SECRETS_TABLE_NAME, [
                'timestamp' => $newTimestamp,
            ], [
                'accountIdentifier' => $account->getAccountIdentifier(),
                'authenticationProviderName' => $account->getAuthenticationProviderName(),
            ]);
        } catch (DBALException $exception) {
            throw new \RuntimeException('Failed to update secret in database', 1550662907, $exception);
        }
        return true;
    }

    /**
     * Generates a QR Code for the configured application name and the specified $holder
     * The QR Code can be used to activate 2FA, @see enableTwoFactorAuthentication()
     */
    public function generateActivationQrCode(string $holder): ActivationQrCode
    {
        $secret = $this->generateSecret();
        $qrCodeUrl = $this->google2FA->getQRCodeUrl($this->applicationName, $holder, $secret->toString());
        return ActivationQrCode::fromSecretAndUrl($secret, $qrCodeUrl);
    }

    /**
     * Enables 2FA for the given $account if $secret and $otp are valid
     * @throws InvalidOtpException if the OTP could not be verified
     */
    public function enableTwoFactorAuthentication(Account $account, Secret $secret, OneTimePassword $otp): void
    {
        try {
            $valid = $this->google2FA->verifyKey($secret->toString(), $otp->toString());
        } catch (IncompatibleWithGoogleAuthenticatorException | InvalidCharactersException | SecretKeyTooShortException $exception) {
            throw new \RuntimeException('Failed to verify secret/otp', 1550662882, $exception);
        }
        if ($valid !== true) {
            throw new InvalidOtpException('Invalid Secret/OTP', 1550653165);
        }
        try {
            $this->dbal->insert(self::SECRETS_TABLE_NAME, [
                'accountIdentifier' => $account->getAccountIdentifier(),
                'authenticationProviderName' => $account->getAuthenticationProviderName(),
                'secret' => $secret->toString(),
                'timestamp' => $this->google2FA->getTimestamp(),
            ]);
        } catch (DBALException $exception) {
            throw new \RuntimeException('Failed to insert secret to database', 1550663161, $exception);
        }
    }

    /**
     * Returns TRUE if the specified $account has 2FA enabled
     */
    public function isTwoFactorAuthenticationEnabledFor(Account $account): bool
    {
        try {
            $userSecret = $this->dbal->fetchColumn('SELECT secret FROM ' . self::SECRETS_TABLE_NAME . ' WHERE accountIdentifier = :accountIdentifier AND authenticationProviderName = :authenticationProviderName LIMIT 1', [
                'accountIdentifier' => $account->getAccountIdentifier(),
                'authenticationProviderName' => $account->getAuthenticationProviderName(),
            ]);
        } catch (DBALException $exception) {
            throw new \RuntimeException('Failed to fetch secret from database, maybe a migration was not executed?', 1550663130, $exception);
        }
        return $userSecret !== false;
    }

    /**
     * @param Account $account
     */
    public function disableTwoFactorAuthentication(Account $account): void
    {
        try {
            $this->dbal->delete(self::SECRETS_TABLE_NAME, [
                'accountIdentifier' => $account->getAccountIdentifier(),
                'authenticationProviderName' => $account->getAuthenticationProviderName(),
            ]);
        } catch (InvalidArgumentException | DBALException $exception) {
            throw new \RuntimeException('Failed to remove secret from database', 1550663349, $exception);
        }
    }

    private function generateSecret(): Secret
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        $secret = $this->google2FA->generateSecretKey($this->secretKeyLength * 8);
        return Secret::fromString($secret);
    }

}
