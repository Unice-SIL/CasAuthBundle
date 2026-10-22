<?php

namespace PRayno\CasAuthBundle\Tests\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use PHPUnit\Framework\TestCase;
use PRayno\CasAuthBundle\Event\CASAuthenticationFailureEvent;
use PRayno\CasAuthBundle\Security\CasAuthenticator;
use PRayno\CasAuthBundle\Security\User\CasUser;
use PRayno\CasAuthBundle\Security\User\CasUserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class CasAuthenticatorTest extends TestCase
{
    private const CONFIG = [
        'server_login_url' => 'https://cas.example.com/login',
        'server_validation_url' => 'https://cas.example.com/serviceValidate',
        'server_logout_url' => 'https://cas.example.com/logout',
        'xml_namespace' => 'cas',
        'options' => [],
        'username_attribute' => 'user',
        'query_ticket_parameter' => 'ticket',
        'query_service_parameter' => 'service',
    ];

    private function mockHttpClient(string $body): Client
    {
        $mock = new MockHandler([new GuzzleResponse(200, [], $body)]);

        return new Client(['handler' => HandlerStack::create($mock)]);
    }

    private function casSuccessXml(string $username, array $attributes = []): string
    {
        $attributesXml = '';
        foreach ($attributes as $name => $value) {
            $attributesXml .= "<cas:{$name}>{$value}</cas:{$name}>";
        }

        return <<<XML
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
    <cas:authenticationSuccess>
        <cas:user>{$username}</cas:user>
        <cas:attributes>{$attributesXml}</cas:attributes>
    </cas:authenticationSuccess>
</cas:serviceResponse>
XML;
    }

    private function casFailureXml(): string
    {
        return <<<XML
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
    <cas:authenticationFailure code="INVALID_TICKET">Ticket not recognized</cas:authenticationFailure>
</cas:serviceResponse>
XML;
    }

    public function testSupportsReturnsTrueWhenTicketIsPresent(): void
    {
        $authenticator = new CasAuthenticator(self::CONFIG, $this->createMock(UserProviderInterface::class), new EventDispatcher());

        $this->assertTrue($authenticator->supports(Request::create('/?ticket=ST-123')));
    }

    public function testSupportsReturnsFalseWhenTicketIsMissing(): void
    {
        $authenticator = new CasAuthenticator(self::CONFIG, $this->createMock(UserProviderInterface::class), new EventDispatcher());

        $this->assertFalse($authenticator->supports(Request::create('/')));
    }

    public function testAuthenticateResolvesUserThroughDefaultUserProvider(): void
    {
        // A real-world UserProviderInterface implementation (like our own CasUserProvider)
        // always defines loadUserByIdentifier() as a concrete method, whether or not the
        // interface itself declares it (it only does so from Symfony 6.0 onwards). A bare
        // createMock(UserProviderInterface::class) would only expose what the installed
        // Symfony version's interface declares, so it can't stand in for this on Symfony 5.4.
        $userProvider = new class implements UserProviderInterface {
            public int $calls = 0;

            public function loadUserByIdentifier(string $identifier): UserInterface
            {
                $this->calls++;

                return new CasUser($identifier, ['ROLE_USER']);
            }

            public function loadUserByUsername($username)
            {
                return $this->loadUserByIdentifier($username);
            }

            public function refreshUser(UserInterface $user): UserInterface
            {
                return $user;
            }

            public function supportsClass(string $class): bool
            {
                return CasUser::class === $class;
            }
        };

        $httpClient = $this->mockHttpClient($this->casSuccessXml('jdoe'));
        $authenticator = new CasAuthenticator(self::CONFIG, $userProvider, new EventDispatcher(), $httpClient);

        $passport = $authenticator->authenticate(Request::create('/?ticket=ST-123'));

        $this->assertSame('jdoe', $passport->getUser()->getUserIdentifier());
        $this->assertSame(1, $userProvider->calls);
    }

    public function testAuthenticatePassesCasAttributesToCasAwareUserProvider(): void
    {
        $userProvider = $this->createMock(CasUserProviderInterface::class);
        $userProvider->expects($this->once())
            ->method('loadUserByUsernameAndAttributes')
            ->with('jdoe', $this->callback(function (array $attributes) {
                return $attributes['mail'] === 'jdoe@example.com';
            }))
            ->willReturn(new CasUser('jdoe', ['ROLE_USER']));

        $httpClient = $this->mockHttpClient($this->casSuccessXml('jdoe', ['mail' => 'jdoe@example.com']));
        $authenticator = new CasAuthenticator(self::CONFIG, $userProvider, new EventDispatcher(), $httpClient);

        $passport = $authenticator->authenticate(Request::create('/?ticket=ST-123'));

        $this->assertSame('jdoe', $passport->getUser()->getUserIdentifier());
    }

    public function testAuthenticateThrowsWhenCasValidationFails(): void
    {
        $userProvider = $this->createMock(UserProviderInterface::class);
        $httpClient = $this->mockHttpClient($this->casFailureXml());
        $authenticator = new CasAuthenticator(self::CONFIG, $userProvider, new EventDispatcher(), $httpClient);

        $this->expectException(CustomUserMessageAuthenticationException::class);

        $authenticator->authenticate(Request::create('/?ticket=ST-invalid'));
    }

    public function testOnAuthenticationSuccessRedirectsWithoutTheTicketParameter(): void
    {
        $authenticator = new CasAuthenticator(self::CONFIG, $this->createMock(UserProviderInterface::class), new EventDispatcher());
        $request = Request::create('/secured?ticket=ST-123&foo=bar');

        $token = $this->createMock(\Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class);
        $response = $authenticator->onAuthenticationSuccess($request, $token, 'main');

        $this->assertNotNull($response);
        $this->assertSame('http://localhost/secured?foo=bar', $response->getTargetUrl());
    }

    public function testOnAuthenticationSuccessReturnsNullWhenThereIsNoTicket(): void
    {
        $authenticator = new CasAuthenticator(self::CONFIG, $this->createMock(UserProviderInterface::class), new EventDispatcher());
        $request = Request::create('/secured');

        $token = $this->createMock(\Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class);
        $response = $authenticator->onAuthenticationSuccess($request, $token, 'main');

        $this->assertNull($response);
    }

    public function testOnAuthenticationFailureReturnsAJsonResponseAndDispatchesTheEvent(): void
    {
        $dispatcher = new EventDispatcher();
        $authenticator = new CasAuthenticator(self::CONFIG, $this->createMock(UserProviderInterface::class), $dispatcher);

        $dispatched = false;
        $dispatcher->addListener(CASAuthenticationFailureEvent::POST_MESSAGE, function (CASAuthenticationFailureEvent $event) use (&$dispatched) {
            $dispatched = true;
            $this->assertInstanceOf(JsonResponse::class, $event->getResponse());
        });

        $exception = new AuthenticationServiceException('CAS down');
        $response = $authenticator->onAuthenticationFailure(Request::create('/'), $exception);

        $this->assertTrue($dispatched);
        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(403, $response->getStatusCode());
    }

    public function testOnAuthenticationFailureUsesTheResponseOverriddenByAListener(): void
    {
        $dispatcher = new EventDispatcher();
        $authenticator = new CasAuthenticator(self::CONFIG, $this->createMock(UserProviderInterface::class), $dispatcher);

        $customResponse = new JsonResponse(['message' => 'custom'], 401);
        $dispatcher->addListener(CASAuthenticationFailureEvent::POST_MESSAGE, function (CASAuthenticationFailureEvent $event) use ($customResponse) {
            $event->setResponse($customResponse);
        });

        $response = $authenticator->onAuthenticationFailure(Request::create('/'), new AuthenticationServiceException('CAS down'));

        $this->assertSame($customResponse, $response);
    }

    public function testStartRedirectsToTheCasLoginUrl(): void
    {
        $authenticator = new CasAuthenticator(self::CONFIG, $this->createMock(UserProviderInterface::class), new EventDispatcher());

        $response = $authenticator->start(Request::create('/secured'));

        $this->assertSame(
            'https://cas.example.com/login?service=http%3A%2F%2Flocalhost%2Fsecured',
            $response->getTargetUrl()
        );
    }
}
