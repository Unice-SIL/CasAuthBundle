<?php

namespace PRayno\CasAuthBundle\Tests\Event;

use PHPUnit\Framework\TestCase;
use PRayno\CasAuthBundle\Event\CASAuthenticationFailureEvent;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Contracts\EventDispatcher\Event;

class CASAuthenticationFailureEventTest extends TestCase
{
    public function testIsAContractsEvent(): void
    {
        $event = new CASAuthenticationFailureEvent(
            Request::create('/'),
            new AuthenticationServiceException('CAS down'),
            new JsonResponse([], 403)
        );

        $this->assertInstanceOf(Event::class, $event);
    }

    public function testGetters(): void
    {
        $request = Request::create('/secured');
        $exception = new AuthenticationServiceException('CAS down');
        $response = new JsonResponse(['message' => 'CAS down'], 403);

        $event = new CASAuthenticationFailureEvent($request, $exception, $response);

        $this->assertSame($request, $event->getRequest());
        $this->assertSame($exception, $event->getException());
        $this->assertSame($response, $event->getResponse());
        $this->assertSame(AuthenticationServiceException::class, $event->getExceptionType());
    }

    public function testSetResponseOverridesTheDefaultResponse(): void
    {
        $event = new CASAuthenticationFailureEvent(
            Request::create('/'),
            new AuthenticationServiceException('CAS down'),
            new JsonResponse([], 403)
        );

        $redirect = new RedirectResponse('/login-failed');
        $event->setResponse($redirect);

        $this->assertSame($redirect, $event->getResponse());
    }
}
