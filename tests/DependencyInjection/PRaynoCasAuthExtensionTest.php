<?php

namespace PRayno\CasAuthBundle\Tests\DependencyInjection;

use PHPUnit\Framework\TestCase;
use PRayno\CasAuthBundle\DependencyInjection\PRaynoCasAuthExtension;
use PRayno\CasAuthBundle\Security\CasAuthenticator;
use PRayno\CasAuthBundle\Security\User\CasUserProvider;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class PRaynoCasAuthExtensionTest extends TestCase
{
    private function buildContainer(array $config = []): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->register(EventDispatcherInterface::class, EventDispatcher::class);
        $container->setAlias('Symfony\\Component\\EventDispatcher\\EventDispatcherInterface', EventDispatcherInterface::class);

        $extension = new PRaynoCasAuthExtension();
        $extension->load([array_merge([
            'server_login_url' => 'https://cas.example.com/login',
            'server_validation_url' => 'https://cas.example.com/serviceValidate',
            'server_logout_url' => 'https://cas.example.com/logout',
        ], $config)], $container);

        return $container;
    }

    public function testUserProviderServiceIsRegistered(): void
    {
        $container = $this->buildContainer();

        $this->assertTrue($container->hasDefinition('prayno.cas_user_provider'));
        $this->assertSame(CasUserProvider::class, $container->getDefinition('prayno.cas_user_provider')->getClass());
    }

    public function testAuthenticatorServiceIsRegisteredWithConfigAndUserProvider(): void
    {
        $container = $this->buildContainer([
            'xml_namespace' => 'custom',
        ]);

        $this->assertTrue($container->hasDefinition('prayno.cas_authenticator'));
        $definition = $container->getDefinition('prayno.cas_authenticator');

        $this->assertSame(CasAuthenticator::class, $definition->getClass());
        $this->assertTrue($definition->isAutowired());

        $arguments = $definition->getArguments();
        $this->assertSame('custom', $arguments['$config']['xml_namespace']);
        $this->assertEquals(new Reference('prayno.cas_user_provider'), $arguments['$userProvider']);
    }

    public function testContainerCompilesAndServicesAreUsable(): void
    {
        $container = $this->buildContainer();
        $container->getDefinition('prayno.cas_authenticator')->setPublic(true);
        $container->getDefinition('prayno.cas_user_provider')->setPublic(true);
        $container->compile();

        $authenticator = $container->get('prayno.cas_authenticator');
        $provider = $container->get('prayno.cas_user_provider');

        $this->assertInstanceOf(CasAuthenticator::class, $authenticator);
        $this->assertInstanceOf(CasUserProvider::class, $provider);
    }
}
