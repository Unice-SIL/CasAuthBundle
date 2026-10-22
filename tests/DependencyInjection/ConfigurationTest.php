<?php

namespace PRayno\CasAuthBundle\Tests\DependencyInjection;

use PHPUnit\Framework\TestCase;
use PRayno\CasAuthBundle\DependencyInjection\Configuration;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Processor;

class ConfigurationTest extends TestCase
{
    public function testGetConfigTreeBuilderReturnsATreeBuilder(): void
    {
        $configuration = new Configuration();

        $this->assertInstanceOf(TreeBuilder::class, $configuration->getConfigTreeBuilder());
    }

    public function testDefaults(): void
    {
        $config = $this->process([[
            'server_login_url' => 'https://cas.example.com/login',
            'server_validation_url' => 'https://cas.example.com/serviceValidate',
            'server_logout_url' => 'https://cas.example.com/logout',
        ]]);

        $this->assertSame('cas', $config['xml_namespace']);
        $this->assertSame([], $config['options']);
        $this->assertSame('user', $config['username_attribute']);
        $this->assertSame('ticket', $config['query_ticket_parameter']);
        $this->assertSame('service', $config['query_service_parameter']);
    }

    public function testExplicitValuesOverrideDefaults(): void
    {
        $config = $this->process([[
            'server_login_url' => 'https://cas.example.com/login',
            'server_validation_url' => 'https://cas.example.com/serviceValidate',
            'server_logout_url' => 'https://cas.example.com/logout',
            'xml_namespace' => 'custom',
            'options' => ['verify' => false],
            'username_attribute' => 'uid',
            'query_ticket_parameter' => 'st',
            'query_service_parameter' => 'svc',
        ]]);

        $this->assertSame('custom', $config['xml_namespace']);
        $this->assertSame(['verify' => false], $config['options']);
        $this->assertSame('uid', $config['username_attribute']);
        $this->assertSame('st', $config['query_ticket_parameter']);
        $this->assertSame('svc', $config['query_service_parameter']);
    }

    private function process(array $configs): array
    {
        return (new Processor())->processConfiguration(new Configuration(), $configs);
    }
}
