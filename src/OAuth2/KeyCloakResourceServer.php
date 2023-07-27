<?php
/**
 * Copyright since 2007 PrestaShop SA and Contributors
 * PrestaShop is an International Registered Trademark & Property of PrestaShop SA
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Academic Free License version 3.0
 * that is bundled with this package in the file LICENSE.md.
 * It is also available through the world-wide-web at this URL:
 * https://opensource.org/licenses/AFL-3.0
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@prestashop.com so we can send you a copy immediately.
 *
 * @author    PrestaShop SA and Contributors <contact@prestashop.com>
 * @copyright Since 2007 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License version 3.0
 */

declare(strict_types=1);

namespace PrestaShop\Module\KeycloakConnectorDemo\OAuth2;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;
use PhpEncryption;
use PrestaShop\Module\KeycloakConnectorDemo\Form\ConfigurationDataConfiguration;
use PrestaShop\Module\KeycloakConnectorDemo\RequestBuilder;
use PrestaShop\PrestaShop\Core\ConfigurationInterface;
use PrestaShop\PrestaShop\Core\Security\OAuth2\ResourceServerInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Symfony\Component\Security\Core\User\UserInterface;

class KeyCloakResourceServer implements ResourceServerInterface
{
    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * @var PhpEncryption
     */
    private $phpEncryption;

    /**
     * @var ConfigurationInterface
     */
    private $configuration;

    /**
     * @var RequestBuilder
     */
    private $requestBuilder;

    public function __construct(
        ClientInterface $client,
        ConfigurationInterface $configuration,
        PhpEncryption $phpEncryption,
        RequestBuilder $requestBuilder
    ) {
        $this->client = $client;
        $this->configuration = $configuration;
        $this->phpEncryption = $phpEncryption;
        $this->requestBuilder = $requestBuilder;
    }

    public function isTokenValid(ServerRequestInterface $request): bool
    {
        $token = $this->getTokenFromRequest($request);
        if ($token === null) {
            return false;
        }

        $certs = $this->getCerts();
        if ($certs === null) {
            return false;
        }

        $certificate = $this->getRightCertificate($token, $certs['keys']);
        if ($certificate === null) {
            return false;
        }

        return (new Validator())->validate($token, ...$this->getValidationConstraints($certificate));
    }

    /**
     * @return array<array<array<string, string>>>|null
     */
    private function getCerts(): ?array
    {
        try {
            $response = $this->client->sendRequest($this->getCertsRequest());
        } catch (ClientExceptionInterface $e) {
            return null;
        }

        if ($response->getStatusCode() !== 200) {
            return null;
        }

        $json = json_decode($response->getBody()->getContents(), true);
        if (!is_array($json) || !isset($json['keys'])) {
            return null;
        }

        return $json;
    }

    /**
     * @param Token $token
     * @param array<array<string, string>> $certs
     *
     * @return Key|null
     */
    private function getRightCertificate(Token $token, array $certs): ?Key
    {
        foreach ($certs as $key) {
            if ($key['kid'] === $token->headers()->get('kid')) {
                return InMemory::plainText(
                    "-----BEGIN CERTIFICATE-----\n" . $key['x5c'][0] . "\n-----END CERTIFICATE-----"
                );
            }
        }

        return null;
    }

    private function getCertsRequest(): RequestInterface
    {
        $endpoint = $this->phpEncryption->decrypt(
            $this->configuration->get(ConfigurationDataConfiguration::REALM_ENDPOINT)
        );

        if (!is_string($endpoint)) {
            throw new RuntimeException('Unable to decrypt realm endpoint configuration');
        }

        return $this->requestBuilder->getCertsRequest($endpoint);
    }

    /**
     * @param Key $key
     *
     * @return array{SignedWith, StrictValidAt}
     */
    private function getValidationConstraints(Key $key): array
    {
        return [
            new SignedWith(new Sha256(), $key),
            new StrictValidAt(SystemClock::fromUTC()),
        ];
    }

    public function getUser(ServerRequestInterface $request): ?UserInterface
    {
        /** @var UnencryptedToken|null $token */
        $token = $this->getTokenFromRequest($request);
        if ($token === null) {
            return null;
        }
        $audience = $token->claims()->get('clientId') ?? $token->claims()->get('client_id');
        if (!is_string($audience)) {
            return null;
        }

        return new KeyCloakUser($audience);
    }

    private function getTokenFromRequest(ServerRequestInterface $request): ?Token
    {
        $authorization = $request->getHeader('Authorization')[0] ?? null;
        if ($authorization === null || strpos($authorization, 'Bearer ') !== 0 || empty(explode(' ', $authorization)[1])) {
            return null;
        }

        return (new Parser(new JoseEncoder()))->parse(explode(' ', $authorization)[1]);
    }
}
