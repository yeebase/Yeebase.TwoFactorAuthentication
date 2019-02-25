<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Domain\ValueObjects;

use Neos\Flow\Annotations as Flow;

/**
 * A Code (aka OTP) returned from an 2FA device or app
 *
 * @Flow\Proxy(false)
 */
final class OneTimePassword
{
    /**
     * @var string
     */
    private $value;

    /**
     * @internal This constructor is only public so that this VO can be property-mapped
     */
    public function __construct(string $otp)
    {
        if (preg_match('/^\d{6}$/', $otp) !== 1) {
            throw new \InvalidArgumentException('OTP must consist of 6 digits', 1549978113);
        }
        $this->value = $otp;
    }

    public static function fromString(string $otp): self
    {
        return new static($otp);
    }

    public function toString(): string
    {
        return $this->value;
    }

}
