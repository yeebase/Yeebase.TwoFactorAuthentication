<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Domain\ValueObjects;

use Neos\Flow\Annotations as Flow;

/**
 * The user specific 2FA secret
 *
 * @Flow\Proxy(false)
 */
final class Secret
{
    /**
     * @var string
     */
    private $value;

    private function __construct(string $secret)
    {
        $secret = trim($secret);
        if ($secret === '') {
            throw new \InvalidArgumentException('Secret must not be empty', 1549978555);
        }
        $this->value = $secret;
    }

    public static function fromString(string $secret): self
    {
        return new static($secret);
    }

    public function toString(): string
    {
        return $this->value;
    }

}
