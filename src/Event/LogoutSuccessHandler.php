<?php

namespace PRayno\CasAuthBundle\Event;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class LogoutSuccessHandler implements EventSubscriberInterface
{
    private string $logoutUrl;

    public function __construct(string $logoutUrl)
    {
        $this->logoutUrl = $logoutUrl;
    }

    public function onLogout(LogoutEvent $event): void
    {
        $event->setResponse(new RedirectResponse($this->logoutUrl));
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => 'onLogout',
        ];
    }
}
