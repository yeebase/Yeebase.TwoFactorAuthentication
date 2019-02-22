<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Domain\ValueObjects;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException;
use Neos\Flow\Security\Exception\InvalidHashException;

/**
 * The user specific 2FA secret - with an appended HMAC
 *
 * @Flow\Proxy(false)
 */
final class SecretWithHmac
{
    /**
     * @var Secret
     */
    private $secret;

    /**
     * @var string
     */
    private $hmac;

    /**
     * @internal This constructor is only public so that this VO can be property-mapped
     * @throws InvalidArgumentForHashGenerationException | InvalidHashException
     */
    public function __construct(string $secretWithHmac)
    {
        $hashService = new HashService();
        $this->secret = Secret::fromString($hashService->validateAndStripHmac($secretWithHmac));
        $this->hmac = substr($secretWithHmac, -40);
    }

    /**
     * @throws InvalidArgumentForHashGenerationException | InvalidHashException
     */
    public static function fromString(string $secretWithHmac): self
    {
        return new static($secretWithHmac);
    }

    public static function fromSecret(Secret $secret): self
    {
        $hashService = new HashService();
        $secretWithHmac = $hashService->appendHmac($secret->toString());
        return new static($secretWithHmac);
    }

    public function getSecret(): Secret
    {
        return $this->secret;
    }

    public function toString(): string
    {
        return $this->secret->toString() . $this->hmac;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

}
