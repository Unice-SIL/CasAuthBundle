<?php

// src/AppBundle/Security/User/CasUser.php
namespace PRayno\CasAuthBundle\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

class CasUser implements UserInterface
{
    private string $username;
    private array $roles;

    /**
     * @param string $username
     * @param array $roles
     */
    public function __construct($username, array $roles)
    {
        $this->username = $username;
        $this->roles = $roles;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    /**
     * @deprecated since Symfony 5.3, use getUserIdentifier() instead. Kept for Symfony 5.4 UserInterface compatibility.
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @deprecated since Symfony 5.3. Kept for Symfony 5.4 UserInterface compatibility; this bundle has no real password.
     */
    public function getPassword(): ?string
    {
        return null;
    }

    /**
     * @deprecated since Symfony 5.3. Kept for Symfony 5.4 UserInterface compatibility; this bundle has no real password.
     */
    public function getSalt(): ?string
    {
        return null;
    }

    public function eraseCredentials(): void
    {
    }
}