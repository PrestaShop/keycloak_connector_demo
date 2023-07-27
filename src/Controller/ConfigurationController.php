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

namespace PrestaShop\Module\KeycloakConnectorDemo\Controller;

use PrestaShop\PrestaShop\Core\Form\FormHandlerInterface;
use PrestaShopBundle\Controller\Admin\FrameworkBundleAdminController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ConfigurationController extends FrameworkBundleAdminController
{
    public function indexAction(Request $request): Response
    {
        /** @var FormHandlerInterface $configurationDataHandler */
        $configurationDataHandler = $this->get('prestashop.module.keycloak_connector_demo.form.configuration_data_handler');
        $configurationForm = $configurationDataHandler->getForm();
        $configurationForm->handleRequest($request);

        if ($configurationForm->isSubmitted() && $configurationForm->isValid()) {
            $errors = $configurationDataHandler->save((array) $configurationForm->getData());
            if (empty($errors)) {
                $this->addFlash('success', $this->trans('Successful update', 'Admin.Notifications.Success'));

                return $this->redirectToRoute('keycloak_connector_configuration');
            }

            $this->flashErrors($errors);
        }

        return $this->render('@Modules/keycloak_connector_demo/views/templates/admin/configuration.html.twig', [
            'configurationForm' => $configurationForm->createView(),
            'layoutTitle' => $this->trans('Keycloak connector', 'Modules.Keycloakconnectordemo.Admin'),
        ]);
    }
}
