<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Domain\ValueObjects;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Neos\Flow\Annotations as Flow;

/**
 * A QR Code that encodes a given secret and can be used to activate 2FA with an authenticator app
 *
 * @Flow\Proxy(false)
 */
final class ActivationQrCode
{
    /**
     * @var Secret
     */
    private $secret;

    /**
     * @var string
     */
    private $qrCodeUrl;

    private function __construct(Secret $secret, string $qrCodeUrl)
    {
        $this->secret = $secret;
        $this->qrCodeUrl = $qrCodeUrl;
    }

    public static function fromSecretAndUrl(Secret $secret, string $qrCodeUrl): self
    {
        return new static($secret, $qrCodeUrl);
    }

    public function getSecret(): Secret
    {
        return $this->secret;
    }

    public function renderSvg(int $width): string
    {
        $renderer = new ImageRenderer(
            new RendererStyle($width),
            new SvgImageBackEnd()
        );
        $bacon = new Writer($renderer);
        return $bacon->writeString(
            $this->qrCodeUrl,
            'utf-8'
        );
    }

}
