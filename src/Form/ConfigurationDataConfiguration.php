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

namespace PrestaShop\Module\KeycloakConnectorDemo\Form;

use PrestaShop\PrestaShop\Core\Configuration\DataConfigurationInterface;
use PrestaShop\PrestaShop\Core\ConfigurationInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class ConfigurationDataConfiguration implements DataConfigurationInterface
{
    public const REALM_ENDPOINT = 'KEYCLOAK_REALM_ENDPOINT';
    public const ALLOWED_ISSUERS = 'KEYCLOAK_ALLOWED_ISSUERS';

    /** @var array<string|array<string, string|string[]>> */
    private $errors = [];

    public function __construct(
        private ConfigurationInterface $configuration,
        private \PhpEncryption $encryption,
        private HttpClientInterface $client
    ) {
    }

    /**
     * {@inheritdoc}
     *
     * @return array<string, string>
     */
    public function getConfiguration(): array
    {
        $endpoint = (string) $this->configuration->get(static::REALM_ENDPOINT);
        if (!empty($endpoint)) {
            $endpoint = $this->encryption->decrypt($endpoint);
            if (!is_string($endpoint)) {
                $endpoint = '';
            }
        }

        $allowedIssuers = (string) $this->configuration->get(static::ALLOWED_ISSUERS);
        if (!empty($allowedIssuers)) {
            $allowedIssuers = $this->encryption->decrypt($allowedIssuers);
            if (!is_string($allowedIssuers)) {
                $allowedIssuers = '';
            }
        }

        return [
            static::REALM_ENDPOINT => $endpoint,
            static::ALLOWED_ISSUERS => $allowedIssuers,
        ];
    }

    /**
     * {@inheritdoc}
     *
     * @param array<string, string> $configuration
     *
     * @return array<string|array<string, string|string[]>>
     */
    public function updateConfiguration(array $configuration): array
    {
        if ($this->validateConfiguration($configuration)) {
            $this->configuration->set(
                static::REALM_ENDPOINT,
                $this->encryption->encrypt(trim($configuration[static::REALM_ENDPOINT], '/ '))
            );
            $this->configuration->set(
                static::ALLOWED_ISSUERS,
                $this->encryption->encrypt($configuration[static::ALLOWED_ISSUERS])
            );
        }

        return $this->errors;
    }

    /**
     * {@inheritdoc}
     *
     * @param array<string, string> $configuration
     */
    public function validateConfiguration(array $configuration): bool
    {
        try {
            $response = $this->client->request('GET', $configuration[static::REALM_ENDPOINT] . '/protocol/openid-connect/certs');
            if ($response->getStatusCode() === 200) {
                return true;
            }

            $errorDetails = $response->getContent(false);
        } catch (TransportExceptionInterface $exception) {
            $errorDetails = $exception->getMessage();
        }

        $this->errors[] = [
            'key' => 'The endpoint seems incorrect: %s',
            'domain' => 'Modules.Advparameters.Notification',
            'parameters' => [$errorDetails],
        ];

        return false;
    }
}
