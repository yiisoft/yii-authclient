<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient;

use Exception;
use InvalidArgumentException;
use Psr\Http\Client\ClientInterface as PsrClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Yiisoft\Factory\FactoryInterface;
use Yiisoft\Json\Json;
use Yiisoft\Yii\AuthClient\Exception\InvalidResponseException;
use Yiisoft\Yii\AuthClient\Signature\HmacSha;
use Yiisoft\Yii\AuthClient\Signature\Signature;
use Yiisoft\Yii\AuthClient\StateStorage\StateStorageInterface;

use function is_array;
use function is_object;

/**
 * BaseOAuth is a base class for the OAuth clients.
 *
 * @link http://oauth.net/
 */
abstract class OAuth extends AuthClient
{
    /**
     * @var string API base URL.
     * This field will be used as {@see UriInterface::getPath()}} value of {@see httpClient}.
     * Note: changing this property will take no effect after {@see httpClient} is instantiated.
     */
    protected string $endpoint;
    /**
     * @var string authorize URL.
     */
    protected string $authUrl;
    /**
     * @var string|null string auth request scope.
     */
    protected ?string $scope = null;
    /**
     * @var bool whether to automatically perform 'refresh access token' request on expired access token.
     */
    protected bool $autoRefreshAccessToken = true;

    /**
     * @var string|null URL, which user will be redirected after authentication at the OAuth provider web site.
     * Note: this should be absolute URL (with http:// or https:// leading).
     * By default current URL will be used.
     */
    protected ?string $returnUrl = null;
    /**
     * @var array|OAuthToken access token instance or its array configuration.
     */
    protected $accessToken;
    /**
     * @var array|Signature signature method instance or its array configuration.
     */
    protected $signatureMethod = [];
    private FactoryInterface $factory;

    /**
     * BaseOAuth constructor.
     *
     * @param PsrClientInterface $httpClient
     * @param RequestFactoryInterface $requestFactory
     * @param StateStorageInterface $stateStorage
     * @param FactoryInterface $factory
     */
    public function __construct(
        PsrClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StateStorageInterface $stateStorage,
        FactoryInterface $factory
    ) {
        $this->factory = $factory;
        parent::__construct($httpClient, $requestFactory, $stateStorage);
    }

    public function getEndpoint(): string
    {
        return $this->endpoint;
    }

    public function setEndpoint(string $endpoint): void
    {
        $this->endpoint = $endpoint;
    }

    public function getAuthUrl(): string
    {
        return $this->authUrl;
    }

    public function setAuthUrl(string $authUrl): void
    {
        $this->authUrl = $authUrl;
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @return string return URL.
     */
    public function getReturnUrl(ServerRequestInterface $request): string
    {
        if ($this->returnUrl === null) {
            $this->returnUrl = $this->defaultReturnUrl($request);
        }
        return $this->returnUrl;
    }

    /**
     * @param string $returnUrl return URL
     */
    public function setReturnUrl(string $returnUrl): void
    {
        $this->returnUrl = $returnUrl;
    }

    /**
     * Composes default {@see returnUrl} value.
     *
     * @param ServerRequestInterface $request
     *
     * @return string return URL.
     */
    protected function defaultReturnUrl(ServerRequestInterface $request): string
    {
        return (string)$request->getUri();
    }

    /**
     * @return array|Signature signature method instance.
     */
    public function getSignatureMethod(): Signature
    {
        if (!is_object($this->signatureMethod)) {
            $this->signatureMethod = $this->createSignatureMethod($this->signatureMethod);
        }

        return $this->signatureMethod;
    }

    /**
     * Set signature method to be used.
     *
     * @param array|Signature $signatureMethod signature method instance or its array configuration.
     *
     * @throws InvalidArgumentException on wrong argument.
     */
    public function setSignatureMethod($signatureMethod): void
    {
        if (!is_object($signatureMethod) && !is_array($signatureMethod)) {
            throw new InvalidArgumentException(
                '"' . static::class . '::signatureMethod"'
                . ' should be instance of "\Yiisoft\Yii\AuthClient\Signature\BaseMethod" or its array configuration. "'
                . gettype($signatureMethod) . '" has been given.'
            );
        }
        $this->signatureMethod = $signatureMethod;
    }

    /**
     * Creates signature method instance from its configuration.
     *
     * @param array $signatureMethodConfig signature method configuration.
     *
     * @return object|Signature signature method instance.
     */
    protected function createSignatureMethod(array $signatureMethodConfig): Signature
    {
        if (!array_key_exists('class', $signatureMethodConfig)) {
            $signatureMethodConfig['class'] = HmacSha::class;
            $signatureMethodConfig['__construct()'] = ['sha1'];
        }
        return $this->factory->create($signatureMethodConfig);
    }

    public function withAutoRefreshAccessToken(): self
    {
        $new = clone $this;
        $new->autoRefreshAccessToken = true;
        return $new;
    }

    public function withoutAutoRefreshAccessToken(): self
    {
        $new = clone $this;
        $new->autoRefreshAccessToken = false;
        return $new;
    }

    /**
     * Performs request to the OAuth API returning response data.
     * You may use {@see createApiRequest()} method instead, gaining more control over request execution.
     *
     * @param string $apiSubUrl API sub URL, which will be append to {@see apiBaseUrl}, or absolute API URL.
     * @param string $method request method.
     * @param array|string $data request data or content.
     * @param array $headers additional request headers.
     *
     * @throws Exception
     *
     * @return array API response data.
     *
     * @see createApiRequest()
     */
    public function api($apiSubUrl, $method = 'GET', $data = [], $headers = []): array
    {
        $request = $this->createApiRequest($method, $apiSubUrl);
        $request = RequestUtil::addHeaders($request, $headers);

        if (!empty($data)) {
            if (is_array($data)) {
                $request = RequestUtil::addParams($request, $data);
            } else {
                $request->getBody()->write($data);
            }
        }

        $request = $this->beforeApiRequestSend($request);
        $response = $this->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new InvalidResponseException(
                $response,
                'Request failed with code: ' . $response->getStatusCode() . ', message: ' . $response->getBody()
            );
        }

        return Json::decode($response->getBody()->getContents());
    }

    /**
     * Creates an HTTP request for the API call.
     * The created request will be automatically processed adding access token parameters and signature
     * before sending. You may use {@see createRequest()} to gain full control over request composition and execution.
     *
     * @param string $method
     * @param string $uri
     *
     * @return RequestInterface HTTP request instance.
     *
     * @see createRequest()
     */
    public function createApiRequest(string $method, string $uri): RequestInterface
    {
        return $this->createRequest($method, $this->endpoint . $uri);
    }

    public function beforeApiRequestSend(RequestInterface $request): RequestInterface
    {
        $accessToken = $this->getAccessToken();
        if (!is_object($accessToken) || !$accessToken->getIsValid()) {
            throw new Exception('Invalid access token.');
        }

        return $this->applyAccessTokenToRequest($request, $accessToken);
    }

    /**
     * @return OAuthToken auth token instance.
     */
    public function getAccessToken(): ?OAuthToken
    {
        if (!is_object($this->accessToken)) {
            $this->accessToken = $this->restoreAccessToken();
        }

        return $this->accessToken;
    }

    /**
     * Sets access token to be used.
     *
     * @param array|OAuthToken $token access token or its configuration.
     */
    public function setAccessToken($token): void
    {
        if (!is_object($token) && $token !== null) {
            $token = $this->createToken($token);
        }
        $this->accessToken = $token;
        $this->saveAccessToken($token);
    }

    /**
     * Restores access token.
     *
     * @return OAuthToken auth token.
     */
    protected function restoreAccessToken(): ?OAuthToken
    {
        $token = $this->getState('token');
        if (is_object($token)) {
            /* @var $token OAuthToken */
            if ($token->getIsExpired() && $this->autoRefreshAccessToken) {
                $token = $this->refreshAccessToken($token);
            }
        }
        return $token;
    }

    /**
     * Gets new auth token to replace expired one.
     *
     * @param OAuthToken $token expired auth token.
     *
     * @return OAuthToken new auth token.
     */
    abstract public function refreshAccessToken(OAuthToken $token): OAuthToken;

    /**
     * Applies access token to the HTTP request instance.
     *
     * @param RequestInterface $request HTTP request instance.
     * @param OAuthToken $accessToken access token instance.
     */
    abstract public function applyAccessTokenToRequest(
        RequestInterface $request,
        OAuthToken $accessToken
    ): RequestInterface;

    /**
     * Creates token from its configuration.
     *
     * @param array $tokenConfig token configuration.
     *
     * @throws \Yiisoft\Factory\Exception\InvalidConfigException
     *
     * @return OAuthToken|object
     */
    protected function createToken(array $tokenConfig = [])
    {
        if (!array_key_exists('class', $tokenConfig)) {
            $tokenConfig['class'] = OAuthToken::class;
        }
        return $this->factory->create($tokenConfig);
    }

    /**
     * Saves token as persistent state.
     *
     * @param OAuthToken|null $token auth token to be saved.
     *
     * @return $this the object itself.
     */
    protected function saveAccessToken($token): self
    {
        return $this->setState('token', $token);
    }

    /**
     * @return string
     */
    public function getScope(): string
    {
        if ($this->scope === null) {
            return $this->getDefaultScope();
        }

        return $this->scope;
    }

    /**
     * @param string $scope
     */
    public function setScope(string $scope): void
    {
        $this->scope = $scope;
    }

    protected function getDefaultScope(): string
    {
        return '';
    }
}
