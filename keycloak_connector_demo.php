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

use PrestaShop\PrestaShop\Adapter\SymfonyContainer;

if (!defined('_PS_VERSION_')) {
    exit;
}

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

class Keycloak_connector_demo extends \Module
{
    public function __construct($name = null, Context $context = null)
    {
        $this->name = 'keycloak_connector_demo';
        $this->displayName = 'Keycloak OAuth2 connector demo';
        $this->version = '1.0.2';
        $this->author = 'PrestaShop';
        $this->description = 'Demo module of how to use Keycloak as OAuth2 Authentication Server for the new API';
        $this->need_instance = 0;
        $this->bootstrap = true;
        $this->ps_versions_compliancy = ['min' => '8.0.0', 'max' => _PS_VERSION_];
        parent::__construct($name, $context);
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
}
