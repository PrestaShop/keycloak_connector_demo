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

use PrestaShop\Module\KeycloakConnectorDemo\Form\ConfigurationDataConfiguration;
use PrestaShop\PrestaShop\Adapter\SymfonyContainer;

if (!defined('_PS_VERSION_')) {
    exit;
}

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

class Keycloak_connector_demo extends \Module
{
    public function __construct()
    {
        $this->name = 'keycloak_connector_demo';
        $this->displayName = 'Keycloak OAuth2 connector demo';
        $this->version = '1.2.0';
        $this->author = 'PrestaShop';
        $this->description = 'Demo module of how to use Keycloak as OAuth2 Authentication Server for the new API';
        $this->need_instance = 0;
        $this->bootstrap = true;
        $this->ps_versions_compliancy = ['min' => '9.0.0', 'max' => _PS_VERSION_];
        parent::__construct();
    }

    public function getContent(): void
    {
        $container = SymfonyContainer::getInstance();
        if ($container === null) {
            throw new RuntimeException('Could not get instance from SymfonyContainer');
        }
        /** @var \Symfony\Component\Routing\RouterInterface $router */
        $router = $container->get('router');
        Tools::redirectAdmin($router->generate('keycloak_connector_configuration'));
    }

    /**
     * @return bool
     */
    public function install()
    {
        if (!parent::install()) {
            return false;
        }

        // Inject default configuration on install (the value is encrypted in the DB);
        $cookieKey = null;
        // On fresh install process _NEW_COOKIE_KEY_ is not available, so we fetch the config directly from the parameters file
        $phpParametersFilepath = _PS_ROOT_DIR_ . '/app/config/parameters.php';
        if (file_exists($phpParametersFilepath)) {
            $config = require $phpParametersFilepath;
            if (!empty($config['parameters']['new_cookie_key'])) {
                $cookieKey = $config['parameters']['new_cookie_key'];
            }
        }

        if (!empty($cookieKey)) {
            $encryption = new PhpEncryption($cookieKey);

            return Configuration::updateValue(ConfigurationDataConfiguration::REALM_ENDPOINT, $encryption->encrypt('http://localhost:8003/realms/prestashop'))
                && Configuration::updateValue(ConfigurationDataConfiguration::ALLOWED_ISSUERS, $encryption->encrypt('http://localhost:8003/realms/prestashop'));
        }

        return true;
    }

    public function uninstall()
    {
        if (!parent::uninstall()) {
            return false;
        }

        // Delete configuration if present
        Configuration::deleteByName(ConfigurationDataConfiguration::REALM_ENDPOINT);

        return true;
    }
}
