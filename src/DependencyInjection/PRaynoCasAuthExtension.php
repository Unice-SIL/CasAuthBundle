<?php

namespace PRayno\CasAuthBundle\DependencyInjection;

use PRayno\CasAuthBundle\Security\CasAuthenticator;
use PRayno\CasAuthBundle\Security\User\CasUserProvider;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * This is the class that loads and manages your bundle configuration.
 *
 * @link http://symfony.com/doc/current/cookbook/bundles/extension.html
 */
class PRaynoCasAuthExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $container->register('prayno.cas_user_provider', CasUserProvider::class);

        $authenticator = $container->autowire('prayno.cas_authenticator', CasAuthenticator::class);
        $authenticator->setArguments(array(
            '$config' => $config,
            '$userProvider' => new Reference('prayno.cas_user_provider'),
        ));
    }
}
