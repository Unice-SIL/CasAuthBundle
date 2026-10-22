<?php

namespace PRayno\CasAuthBundle\Tests\Security\User;

use PHPUnit\Framework\TestCase;
use PRayno\CasAuthBundle\Security\User\CasUser;
use Symfony\Component\Security\Core\User\UserInterface;

class CasUserTest extends TestCase
{
    public function testImplementsUserInterface(): void
    {
        $user = new CasUser('jdoe', ['ROLE_USER']);

        $this->assertInstanceOf(UserInterface::class, $user);
    }

    public function testGetUserIdentifier(): void
    {
        $user = new CasUser('jdoe', ['ROLE_USER']);

        $this->assertSame('jdoe', $user->getUserIdentifier());
    }

    public function testGetUsernameIsKeptForLegacyBc(): void
    {
        $user = new CasUser('jdoe', ['ROLE_USER']);

        $this->assertSame('jdoe', $user->getUsername());
    }

    public function testGetRoles(): void
    {
        $user = new CasUser('jdoe', ['ROLE_USER', 'ROLE_ADMIN']);

        $this->assertSame(['ROLE_USER', 'ROLE_ADMIN'], $user->getRoles());
    }

    public function testGetPasswordAndSaltAreNull(): void
    {
        $user = new CasUser('jdoe', ['ROLE_USER']);

        $this->assertNull($user->getPassword());
        $this->assertNull($user->getSalt());
    }

    public function testEraseCredentialsDoesNothing(): void
    {
        $user = new CasUser('jdoe', ['ROLE_USER']);

        $user->eraseCredentials();

        $this->assertSame('jdoe', $user->getUserIdentifier());
    }
}
