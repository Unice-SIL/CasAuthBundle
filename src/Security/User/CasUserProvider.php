<?php
// src/AppBundle/Security/User/CasProvider.php
namespace PRayno\CasAuthBundle\Security\User;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;

class CasUserProvider implements UserProviderInterface
{
    /**
     * Provides the authenticated user a ROLE_USER
     * @param string $identifier
     * @return CasUser
     * @throws UserNotFoundException
     */
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        if ($identifier) {
            return new CasUser($identifier, ["ROLE_USER"]);
        }

        throw new UserNotFoundException(
            sprintf('Username "%s" does not exist.', $identifier)
        );
    }

    /**
     * @deprecated kept for compatibility with Symfony 5.4, use loadUserByIdentifier() instead
     * @param string $username
     * @return CasUser
     * @throws UserNotFoundException
     */
    public function loadUserByUsername($username)
    {
        return $this->loadUserByIdentifier($username);
    }

    /**
     * @param UserInterface $user
     * @return CasUser
     * @throws UnsupportedUserException
     * @throws UserNotFoundException
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof CasUser) {
            throw new UnsupportedUserException(
                sprintf('Instances of "%s" are not supported.', get_class($user))
            );
        }

        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return $class === CasUser::class;
    }
}