<?php

namespace PRayno\CasAuthBundle\Security;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use PRayno\CasAuthBundle\Event\CASAuthenticationFailureEvent;
use PRayno\CasAuthBundle\Security\User\CasUserProviderInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class CasAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    protected $server_login_url;
    protected $server_validation_url;
    protected $xml_namespace;
    protected $username_attribute;
    protected $query_ticket_parameter;
    protected $query_service_parameter;
    protected $options;

    private UserProviderInterface $userProvider;
    private EventDispatcherInterface $eventDispatcher;
    private ClientInterface $httpClient;

    /**
     * Process configuration
     * @param array $config
     */
    public function __construct(array $config, UserProviderInterface $userProvider, EventDispatcherInterface $eventDispatcher, ?ClientInterface $httpClient = null)
    {
        $this->server_login_url = $config['server_login_url'];
        $this->server_validation_url = $config['server_validation_url'];
        $this->xml_namespace = $config['xml_namespace'];
        $this->username_attribute = $config['username_attribute'];
        $this->query_service_parameter = $config['query_service_parameter'];
        $this->query_ticket_parameter = $config['query_ticket_parameter'];
        $this->options = $config['options'];

        $this->userProvider = $userProvider;
        $this->eventDispatcher = $eventDispatcher;
        $this->httpClient = $httpClient ?? new Client();
    }

    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     */
    public function supports(Request $request): ?bool
    {
        return (bool) $request->get($this->query_ticket_parameter);
    }

    /**
     * Validates the CAS ticket and builds the security passport.
     */
    public function authenticate(Request $request): Passport
    {
        $credentials = $this->getCredentials($request);

        if (!isset($credentials[$this->username_attribute])) {
            throw new CustomUserMessageAuthenticationException('CAS ticket validation failed.');
        }

        $username = $credentials[$this->username_attribute];
        $attributes = isset($credentials['attributes']) ? (array) $credentials['attributes'] : [];
        $userProvider = $this->userProvider;

        return new SelfValidatingPassport(
            new UserBadge($username, function (string $identifier) use ($userProvider, $attributes) {
                if ($userProvider instanceof CasUserProviderInterface) {
                    return $userProvider->loadUserByUsernameAndAttributes($identifier, $attributes);
                }

                if (method_exists($userProvider, 'loadUserByIdentifier')) {
                    return $userProvider->loadUserByIdentifier($identifier);
                }

                return $userProvider->loadUserByUsername($identifier);
            })
        );
    }

    /**
     * Validates the CAS ticket against the CAS server and returns the authentication attributes.
     */
    private function getCredentials(Request $request): array
    {
        $url = $this->server_validation_url.'?'.$this->query_ticket_parameter.'='.
            $request->get($this->query_ticket_parameter).'&'.
            $this->query_service_parameter.'='.urlencode($this->removeCasTicket($request->getUri()));

        $response = $this->httpClient->request('GET', $url, $this->options);

        $string = $response->getBody()->getContents();

        $xml = new \SimpleXMLElement($string, 0, false, $this->xml_namespace, true);

        if (isset($xml->authenticationSuccess)) {
            return (array) $xml->authenticationSuccess;
        }
        return [];
    }

    /**
     * Mandatory but not in use in a remote authentication
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // If authentication was successful, redirect to the current URI with
        // the ticket parameter removed so that it is hidden from end-users.
        if ($request->query->has($this->query_ticket_parameter)) {
            return new RedirectResponse($this->removeCasTicket($request->getUri()));
        } else {
            return null;
        }
    }

    /**
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $data = array(
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())
        );
        $def_response = new JsonResponse($data, 403);

        $event = new CASAuthenticationFailureEvent($request, $exception, $def_response);
        $this->eventDispatcher->dispatch($event, CASAuthenticationFailureEvent::POST_MESSAGE);

        return $event->getResponse();
    }

    /**
     * Called when authentication is needed, redirect to your CAS server authentication form
     */
    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->server_login_url.'?'.$this->query_service_parameter.'='.urlencode($request->getUri()));
    }

    /**
     * Strip the CAS 'ticket' parameter from a uri.
     */
    protected function removeCasTicket($uri) {
      $parsed_url = parse_url($uri);
      // If there are no query parameters, then there is nothing to do.
      if (empty($parsed_url['query'])) {
          return $uri;
      }
      parse_str($parsed_url['query'], $query_params);
      // If there is no 'ticket' parameter, there is nothing to do.
      if (!isset($query_params[$this->query_ticket_parameter])) {
          return $uri;
      }
      // Remove the ticket parameter and rebuild the query string.
      unset($query_params[$this->query_ticket_parameter]);
      if (empty($query_params)) {
          unset($parsed_url['query']);
      } else {
          $parsed_url['query'] = http_build_query($query_params);
      }

      // Rebuild the URI from the parsed components.
      // Source: https://secure.php.net/manual/en/function.parse-url.php#106731
      $scheme   = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : '';
      $host     = isset($parsed_url['host']) ? $parsed_url['host'] : '';
      $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
      $user     = isset($parsed_url['user']) ? $parsed_url['user'] : '';
      $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass']  : '';
      $pass     = ($user || $pass) ? "$pass@" : '';
      $path     = isset($parsed_url['path']) ? $parsed_url['path'] : '';
      $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
      $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
      return "$scheme$user$pass$host$port$path$query$fragment";
    }
}
