<?php

namespace PRayno\CasAuthBundle\Tests\Event;

use PHPUnit\Framework\TestCase;
use PRayno\CasAuthBundle\Event\LogoutSuccessHandler;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class LogoutSuccessHandlerTest extends TestCase
{
    public function testImplementsEventSubscriberInterface(): void
    {
        $handler = new LogoutSuccessHandler('https://cas.example.com/logout');

        $this->assertInstanceOf(EventSubscriberInterface::class, $handler);
    }

    public function testGetSubscribedEvents(): void
    {
        $this->assertSame(
            [LogoutEvent::class => 'onLogout'],
            LogoutSuccessHandler::getSubscribedEvents()
        );
    }

    public function testOnLogoutSetsARedirectResponseToTheCasLogoutUrl(): void
    {
        $handler = new LogoutSuccessHandler('https://cas.example.com/logout');
        $event = new LogoutEvent(Request::create('/logout'), null);

        $handler->onLogout($event);

        $response = $event->getResponse();
        $this->assertNotNull($response);
        $this->assertSame('https://cas.example.com/logout', $response->getTargetUrl());
    }
}
