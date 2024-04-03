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

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;
use PhpEncryption;
use PrestaShop\Module\KeycloakConnectorDemo\Form\ConfigurationDataConfiguration;
use PrestaShop\Module\KeycloakConnectorDemo\RequestBuilder;
use PrestaShop\PrestaShop\Core\ConfigurationInterface;
use PrestaShop\PrestaShop\Core\Security\OAuth2\AuthorisationServerInterface;
use PrestaShop\PrestaShop\Core\Security\OAuth2\JwtTokenUser;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

class KeycloakAuthorizationServer implements AuthorisationServerInterface
{
    private ?Parser $jwtParser = null;

    private ?string $certificatesUrl = null;

    private ?Validator $validator = null;

    private array $parsedTokens = [];

    public function __construct(
        private readonly ClientInterface $client,
        private readonly ConfigurationInterface $configuration,
        private readonly PhpEncryption $phpEncryption,
        private readonly RequestBuilder $requestBuilder,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function isTokenValid(Request $request): bool
    {
        $token = $this->getTokenFromRequest($request);
        if ($token === null) {
            return false;
        }

        $certsUrl = $this->getCertificatesUrl();
        if (empty($certsUrl)) {
            $this->logger->debug('KeycloakAuthorizationServer: no certs URL detected');

            return false;
        }

        if (!$token->hasBeenIssuedBy($certsUrl)) {
            $this->logger->info('KeycloakAuthorizationServer: invalid issuer got ' . $token->claims()->get(RegisteredClaims::ISSUER) . ' instead of ' . $certsUrl . ' claims ' . $token->claims()->toString());

            //return false;
        }

        $certs = $this->getServerCertificates($certsUrl);
        if ($certs === null) {
            return false;
        }

        $certificate = $this->getRightCertificate($token, $certs['keys']);
        if ($certificate === null) {
            return false;
        }

        return $this->getValidator()->validate($token, ...$this->getValidationConstraints($certificate));
    }

    public function getJwtTokenUser(Request $request): ?JwtTokenUser
    {
        /** @var UnencryptedToken|null $token */
        $token = $this->getTokenFromRequest($request);
        if ($token === null) {
            return null;
        }

        $clientId = $token->claims()->get('clientId') ?? $token->claims()->get('client_id');
        if (!is_string($clientId)) {
            return null;
        }

        $scope = $token->claims()->get('scope');
        if (empty($scope)) {
            return null;
        }
        $scopes = explode(' ', $scope);

        return new JwtTokenUser($clientId, $scopes, $token->claims()->get('iss'));
    }

    /**
     * @return array<array<array<string, string>>>|null
     */
    private function getServerCertificates(string $certsUrl): ?array
    {
        try {
            $request = $this->requestBuilder->getCertsRequest($certsUrl);
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            $this->logger->debug('KeycloakAuthorizationServer: get server certificates failed: ' . $e->getMessage());

            return null;
        }

        if ($response->getStatusCode() !== 200) {
            $this->logger->debug('KeycloakAuthorizationServer: server certificates request failed: ' . $response->getStatusCode());

            return null;
        }

        $json = json_decode($response->getBody()->getContents(), true);
        if (!is_array($json) || !isset($json['keys'])) {
            $this->logger->debug('KeycloakAuthorizationServer: server certificates invalid JSON format: ' . $response->getBody()->getContents());

            return null;
        }

        return $json;
    }

    /**
     * @param TokenInterface $token
     * @param array<array<string, string>> $certs
     *
     * @return Key|null
     */
    private function getRightCertificate(TokenInterface $token, array $certs): ?Key
    {
        foreach ($certs as $key) {
            if ($key['kid'] === $token->headers()->get('kid')) {
                return InMemory::plainText(
                    "-----BEGIN CERTIFICATE-----\n" . $key['x5c'][0] . "\n-----END CERTIFICATE-----"
                );
            }
        }
        $this->logger->error('KeycloakAuthorizationServer: could not find right certificate kid in: ' . var_export($certs, true));

        return null;
    }

    private function getCertificatesUrl(): ?string
    {
        if (!empty($this->certificatesUrl)) {
            return $this->certificatesUrl;
        }

        $encryptedEndpoint = $this->configuration->get(ConfigurationDataConfiguration::REALM_ENDPOINT);
        if (empty($encryptedEndpoint)) {
            return null;
        }

        $endpoint = $this->phpEncryption->decrypt($encryptedEndpoint);
        if (!is_string($endpoint)) {
            $this->logger->error('KeycloakAuthorizationServer: could not decrypt endpoint ' . $encryptedEndpoint);

            return null;
        }
        $this->certificatesUrl = $endpoint;

        return $this->certificatesUrl;
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
        ];
    }

    private function getTokenFromRequest(Request $request): ?TokenInterface
    {
        $authorization = $request->headers->get('Authorization') ?? null;
        if ($authorization === null || !str_starts_with($authorization, 'Bearer ')) {
            $this->logger->debug('KeycloakAuthorizationServer: no authorization bearer token in request');

            return null;
        }

        $explodedToken = explode(' ', $authorization);
        if (count($explodedToken) < 2) {
            $this->logger->debug('KeycloakAuthorizationServer: explosion failed');

            return null;
        }

        $bearerToken = $explodedToken[1];
        if (empty($bearerToken)) {
            $this->logger->debug('KeycloakAuthorizationServer: empty bearer token');

            return null;
        }

        if (empty($this->parsedTokens[$bearerToken])) {
            try {
                $token = $this->getJwtParser()->parse($bearerToken);
            } catch (InvalidTokenStructure $e) {
                $this->logger->error('KeycloakAuthorizationServer: invalid token structure: ' . $e->getMessage());

                return null;
            }
            $this->parsedTokens[$bearerToken] = $token;
        }

        return $this->parsedTokens[$bearerToken];
    }

    private function getJwtParser(): Parser
    {
        if (!$this->jwtParser) {
            $this->jwtParser = new Parser(new JoseEncoder());
        }

        return $this->jwtParser;
    }

    private function getValidator(): Validator
    {
        if (!$this->validator) {
            $this->validator = new Validator();
        }

        return $this->validator;
    }
}
