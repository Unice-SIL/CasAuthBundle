<?php

namespace PRayno\CasAuthBundle\Tests\Security\User;

use PHPUnit\Framework\TestCase;
use PRayno\CasAuthBundle\Security\User\CasUser;
use PRayno\CasAuthBundle\Security\User\CasUserProvider;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;

class CasUserProviderTest extends TestCase
{
    public function testLoadUserByIdentifierReturnsCasUserWithRoleUser(): void
    {
        $provider = new CasUserProvider();

        $user = $provider->loadUserByIdentifier('jdoe');

        $this->assertInstanceOf(CasUser::class, $user);
        $this->assertSame('jdoe', $user->getUserIdentifier());
        $this->assertSame(['ROLE_USER'], $user->getRoles());
    }

    public function testLoadUserByIdentifierThrowsWhenIdentifierIsEmpty(): void
    {
        $provider = new CasUserProvider();

        $this->expectException(UserNotFoundException::class);

        $provider->loadUserByIdentifier('');
    }

    public function testLoadUserByUsernameDelegatesToLoadUserByIdentifier(): void
    {
        $provider = new CasUserProvider();

        $user = $provider->loadUserByUsername('jdoe');

        $this->assertInstanceOf(CasUser::class, $user);
        $this->assertSame('jdoe', $user->getUserIdentifier());
    }

    public function testRefreshUserReloadsACasUser(): void
    {
        $provider = new CasUserProvider();
        $original = new CasUser('jdoe', ['ROLE_USER']);

        $refreshed = $provider->refreshUser($original);

        $this->assertInstanceOf(CasUser::class, $refreshed);
        $this->assertSame('jdoe', $refreshed->getUserIdentifier());
    }

    public function testRefreshUserThrowsForUnsupportedUser(): void
    {
        $provider = new CasUserProvider();
        $notACasUser = $this->createMock(UserInterface::class);

        $this->expectException(UnsupportedUserException::class);

        $provider->refreshUser($notACasUser);
    }

    public function testSupportsClass(): void
    {
        $provider = new CasUserProvider();

        $this->assertTrue($provider->supportsClass(CasUser::class));
        $this->assertFalse($provider->supportsClass(\stdClass::class));
    }
}
