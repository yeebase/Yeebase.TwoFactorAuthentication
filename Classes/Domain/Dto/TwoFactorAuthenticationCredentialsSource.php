<?php
namespace Yeebase\TwoFactorAuthentication\Domain\Dto;

class TwoFactorAuthenticationCredentialsSource
{

    /**
     * @var string
     */
    public $credentialsSource;

    /**
     * @var bool
     */
    public $enabled;

    /**
     * @var string
     */
    public $secret;

    /**
     * @var string
     */
    public $pendingSecret;

    public function __construct(string $credentialsSource, bool $enabled, string $secret, string $pendingSecret)
    {
        $this->credentialsSource = $credentialsSource;
        $this->enabled = $enabled;
        $this->secret = $secret;
        $this->pendingSecret = $pendingSecret;
    }

    /**
     * @param string $jsonString
     * @return TwoFactorAuthenticationCredentialsSource
     */
    public static function fromJsonString($jsonString)
    {
        $jsonArray = json_decode($jsonString, true);

        return new self(
            $jsonArray['credentialsSource'],
            $jsonArray['enabled'],
            $jsonArray['secret'],
            $jsonArray['pendingSecret']
        );
    }

    public function toJsonString(): string
    {
        return json_encode([
            'credentialsSource' => $this->credentialsSource,
            'enabled' => $this->enabled,
            'secret' => $this->secret,
            'pendingSecret' => $this->pendingSecret
        ]);
    }
}
