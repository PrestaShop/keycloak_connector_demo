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
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
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

    /**
     * @var non-empty-string[]|null
     */
    private ?array $allowedIssuers = null;

    private ?Validator $validator = null;

    /**
     * @var array<string, UnencryptedToken>
     */
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
        // Parses the JWT Token and check if it's valid
        $token = $this->getTokenFromRequest($request);
        if ($token === null) {
            return false;
        }

        // Fetch the list of allowed issuers from the configuration
        $allowedIssuers = $this->getKeycloakAllowedIssuers();
        if (empty($allowedIssuers)) {
            $this->logger->debug('KeycloakAuthorizationServer: no allowed issuers defined');

            return false;
        }

        // If the Token issuer matches one of the allowed ones
        $tokenIssuerAllowed = false;
        foreach ($allowedIssuers as $allowedIssuer) {
            if ($token->hasBeenIssuedBy($allowedIssuer)) {
                $tokenIssuerAllowed = true;
                break;
            }
        }

        if (!$tokenIssuerAllowed) {
            $this->logger->debug('KeycloakAuthorizationServer: invalid issuer got ' . $token->claims()->get(RegisteredClaims::ISSUER) . ' instead one of "' . implode(',', $allowedIssuers));

            return false;
        }

        // Fetch the URL realm from the configuration
        $certsUrl = $this->getKeycloakRealmUrl();
        if (empty($certsUrl)) {
            $this->logger->debug('KeycloakAuthorizationServer: no certs URL detected');

            return false;
        }

        // Download the certificates from the authorization server
        $certs = $this->getServerCertificates($certsUrl);
        if ($certs === null) {
            return false;
        }

        $certificate = $this->getRightCertificate($token, $certs['keys']);
        if ($certificate === null) {
            return false;
        }

        // Check if the JWT token was correctly signed based on the public certificate
        return $this->getValidator()->validate($token, ...$this->getValidationConstraints($certificate));
    }

    /**
     * Parses the JWT token from the request, it should contain these claims
     *   - clientId: The used client ID to get the access token
     *   - scope: a list of scope separated by spaces
     *   - iss: the issuer that granted the access token
     *
     * @param Request $request
     *
     * @return JwtTokenUser|null
     */
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
        if (!is_string($scope) || empty($scope)) {
            return null;
        }
        $scopes = explode(' ', $scope);

        $issuer = $token->claims()->get('iss');
        if (!is_string($issuer) || empty($issuer)) {
            return null;
        }

        return new JwtTokenUser($clientId, $scopes, $issuer);
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
     * @param UnencryptedToken $token
     * @param array<array<string, string>> $certs
     *
     * @return Key|null
     */
    private function getRightCertificate(UnencryptedToken $token, array $certs): ?Key
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

    private function getKeycloakRealmUrl(): ?string
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
     * @return non-empty-string[]|null
     */
    private function getKeycloakAllowedIssuers(): ?array
    {
        if (!empty($this->allowedIssuers)) {
            return $this->allowedIssuers;
        }

        $encryptedIssuers = $this->configuration->get(ConfigurationDataConfiguration::ALLOWED_ISSUERS);
        if (empty($encryptedIssuers)) {
            return null;
        }

        $issuers = $this->phpEncryption->decrypt($encryptedIssuers);
        if (!is_string($issuers)) {
            $this->logger->error('KeycloakAuthorizationServer: could not decrypt issuers ' . $encryptedIssuers);

            return null;
        }
        /** @var non-empty-string[] $allowedIssuers */
        $allowedIssuers = explode(' ', $issuers);
        $this->allowedIssuers = $allowedIssuers;

        return $this->allowedIssuers;
    }

    /**
     * @param Key $key
     *
     * @return Constraint[]
     */
    private function getValidationConstraints(Key $key): array
    {
        return [
            new SignedWith(new Sha256(), $key),
        ];
    }

    private function getTokenFromRequest(Request $request): ?UnencryptedToken
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
                /** @var Plain $token */
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
