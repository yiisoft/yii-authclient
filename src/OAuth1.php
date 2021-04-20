<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient;

use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Json\Json;

/**
 * OAuth1 serves as a client for the OAuth 1/1.0a flow.
 *
 * In order to acquire access token perform following sequence:
 *
 * ```php
 * use Yiisoft\Yii\AuthClient\OAuth1;
 *
 * // assuming class MyAuthClient extends OAuth1
 * $oauthClient = new MyAuthClient();
 * $requestToken = $oauthClient->fetchRequestToken(); // Get request token
 * $url = $oauthClient->buildAuthUrl($requestToken); // Get authorization URL
 * return Yii::getApp()->getResponse()->redirect($url); // Redirect to authorization URL
 *
 * // After user returns at our site:
 * $accessToken = $oauthClient->fetchAccessToken(Yii::getApp()->request->get('oauth_token'), $requestToken); // Upgrade to access token
 * ```
 *
 * @see https://oauth.net/1/
 * @see https://tools.ietf.org/html/rfc5849
 */
abstract class OAuth1 extends OAuth
{
    private const PROTOCOL_VERSION = '1.0';

    /**
     * @var string OAuth consumer key.
     */
    protected string $consumerKey = '';
    /**
     * @var string OAuth consumer secret.
     */
    protected string $consumerSecret = '';
    /**
     * @var string OAuth request token URL.
     */
    protected string $requestTokenUrl;
    /**
     * @var string request token HTTP method.
     */
    protected string $requestTokenMethod = 'GET';
    /**
     * @var string OAuth access token URL.
     */
    protected string $accessTokenUrl;
    /**
     * @var string access token HTTP method.
     */
    protected string $accessTokenMethod = 'GET';
    /**
     * @var array|null list of the request methods, which require adding 'Authorization' header.
     * By default only POST requests will have 'Authorization' header.
     * You may set this option to `null` in order to make all requests to use 'Authorization' header.
     */
    protected ?array $authorizationHeaderMethods = ['POST'];

    /**
     * Composes user authorization URL.
     *
     * @param ServerRequestInterface $incomingRequest
     * @param array $params additional request params.
     *
     * @return string authorize URL
     */
    public function buildAuthUrl(
        ServerRequestInterface $incomingRequest,
        array $params = []
    ): string {
        $requestToken = $this->fetchRequestToken($incomingRequest);
        $params['oauth_token'] = $requestToken->getToken();

        return RequestUtil::composeUrl($this->authUrl, $params);
    }

    /**
     * Fetches the OAuth request token.
     *
     * @param ServerRequestInterface $incomingRequest
     * @param array $params additional request params.
     *
     * @throws \Yiisoft\Factory\Exception\InvalidConfigException
     *
     * @return OAuthToken request token.
     */
    public function fetchRequestToken(ServerRequestInterface $incomingRequest, array $params = []): OAuthToken
    {
        $this->setAccessToken(null);
        $defaultParams = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_callback' => $this->getReturnUrl($incomingRequest),
            'xoauth_displayname' => $incomingRequest->getAttribute(AuthAction::AUTH_NAME),
        ];
        if (!empty($this->getScope())) {
            $defaultParams['scope'] = $this->getScope();
        }

        $request = $this->createRequest(
            $this->requestTokenMethod,
            $this->requestTokenUrl . '?' . http_build_query(
                array_merge($defaultParams, $params)
            )
        );

        $request = $this->signRequest($request);
        $response = $this->sendRequest($request);

        $tokenConfig = Json::decode((string) $response->getBody());

        if (empty($tokenConfig)) {
            throw new InvalidArgumentException('Request token is required to build authorize URL!');
        }

        $token = $this->createToken($tokenConfig);
        $this->setState('requestToken', $token);

        return $token;
    }

    /**
     * Sign given request with {@see signatureMethod}.
     *
     * @param RequestInterface $request request instance.
     * @param OAuthToken|null $token OAuth token to be used for signature, if not set {@see accessToken} will be used.
     *
     * @return RequestInterface
     */
    public function signRequest(RequestInterface $request, ?OAuthToken $token = null): RequestInterface
    {
        $params = RequestUtil::getParams($request);

        if (isset($params['oauth_signature_method']) || $request->hasHeader('authorization')) {
            // avoid double sign of request
            return $request;
        }

        if (empty($request->getUri()->getQuery())) {
            $params = $this->generateCommonRequestParams();
        } else {
            $params = array_merge($this->generateCommonRequestParams(), $params);
        }

        $url = (string)$request->getUri();

        $signatureMethod = $this->getSignatureMethod();

        $params['oauth_signature_method'] = $signatureMethod->getName();
        $signatureBaseString = $this->composeSignatureBaseString($request->getMethod(), $url, $params);
        $signatureKey = $this->composeSignatureKey($token);
        $params['oauth_signature'] = $signatureMethod->generateSignature($signatureBaseString, $signatureKey);

        if (
            $this->authorizationHeaderMethods === null || in_array(
                strtoupper($request->getMethod()),
                array_map(
                    'strtoupper',
                    $this->authorizationHeaderMethods
                ),
                true
            )
        ) {
            $authorizationHeader = $this->composeAuthorizationHeader($params);
            if (!empty($authorizationHeader)) {
                foreach ($authorizationHeader as $name => $value) {
                    $request = $request->withHeader($name, $value);
                }

                // removing authorization header params, avoiding duplicate param server error :
                foreach ($params as $key => $value) {
                    if (substr_compare($key, 'oauth', 0, 5) === 0) {
                        unset($params[$key]);
                    }
                }
            }
        }

        $uri = $request->getUri()->withQuery(http_build_query($params));
        return $request->withUri($uri);
    }

    /**
     * Generate common request params like version, timestamp etc.
     *
     * @return array common request params.
     */
    protected function generateCommonRequestParams(): array
    {
        return [
            'oauth_version' => self::PROTOCOL_VERSION,
            'oauth_nonce' => $this->generateNonce(),
            'oauth_timestamp' => $this->generateTimestamp(),
        ];
    }

    /**
     * Generates nonce value.
     *
     * @return string nonce value.
     */
    protected function generateNonce(): string
    {
        return md5(microtime() . mt_rand());
    }

    /**
     * Generates timestamp.
     *
     * @return int timestamp.
     */
    protected function generateTimestamp(): int
    {
        return time();
    }

    /**
     * Creates signature base string, which will be signed by {@see signatureMethod}.
     *
     * @param string $method request method.
     * @param string $url request URL.
     * @param array $params request params.
     *
     * @return string base signature string.
     */
    protected function composeSignatureBaseString($method, $url, array $params)
    {
        if (strpos($url, '?') !== false) {
            [$url, $queryString] = explode('?', $url, 2);
            parse_str($queryString, $urlParams);
            $params = array_merge($urlParams, $params);
        }
        unset($params['oauth_signature']);
        uksort(
            $params,
            'strcmp'
        ); // Parameters are sorted by name, using lexicographical byte value ordering. Ref: Spec: 9.1.1
        $parts = [
            strtoupper($method),
            $url,
            http_build_query($params, '', '&', PHP_QUERY_RFC3986),
        ];
        $parts = array_map('rawurlencode', $parts);

        return implode('&', $parts);
    }

    /**
     * Composes request signature key.
     *
     * @param OAuthToken|null $token OAuth token to be used for signature key.
     *
     * @return string signature key.
     */
    protected function composeSignatureKey($token = null): string
    {
        $signatureKeyParts = [
            $this->consumerSecret,
        ];

        if ($token === null) {
            $token = $this->getAccessToken();
        }
        if (is_object($token)) {
            $signatureKeyParts[] = $token->getTokenSecret();
        } else {
            $signatureKeyParts[] = '';
        }

        $signatureKeyParts = array_map('rawurlencode', $signatureKeyParts);

        return implode('&', $signatureKeyParts);
    }

    /**
     * Composes authorization header.
     *
     * @param array $params request params.
     * @param string $realm authorization realm.
     *
     * @return array authorization header in format: [name => content].
     */
    public function composeAuthorizationHeader(array $params, $realm = '')
    {
        $header = 'OAuth';
        $headerParams = [];
        if (!empty($realm)) {
            $headerParams[] = 'realm="' . rawurlencode($realm) . '"';
        }
        foreach ($params as $key => $value) {
            if (substr_compare($key, 'oauth', 0, 5)) {
                continue;
            }
            $headerParams[] = rawurlencode((string)$key) . '="' . rawurlencode((string)$value) . '"';
        }
        if (!empty($headerParams)) {
            $header .= ' ' . implode(', ', $headerParams);
        }

        return ['Authorization' => $header];
    }

    /**
     * Fetches OAuth access token.
     *
     * @param ServerRequestInterface $incomingRequest
     * @param string|null $oauthToken OAuth token returned with redirection back to client.
     * @param OAuthToken|null $requestToken OAuth request token.
     * @param string|null $oauthVerifier OAuth verifier.
     * @param array $params additional request params.
     *
     * @return OAuthToken OAuth access token.
     */
    public function fetchAccessToken(
        ServerRequestInterface $incomingRequest,
        string $oauthToken = null,
        OAuthToken $requestToken = null,
        string $oauthVerifier = null,
        array $params = []
    ): OAuthToken {
        $queryParams = $incomingRequest->getQueryParams();
        $bodyParams = $incomingRequest->getParsedBody();
        if ($oauthToken === null) {
            $oauthToken = $queryParams['oauth_token'] ?? $bodyParams['oauth_token'] ?? null;
        }

        if (!is_object($requestToken)) {
            $requestToken = $this->getState('requestToken');
            if (!is_object($requestToken)) {
                throw new InvalidArgumentException('Request token is required to fetch access token!');
            }
        }

        if (strcmp($requestToken->getToken(), $oauthToken) !== 0) {
            throw new InvalidArgumentException('Invalid auth state parameter.');
        }

        $this->removeState('requestToken');

        $defaultParams = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_token' => $requestToken->getToken(),
        ];
        if ($oauthVerifier === null) {
            $oauthVerifier = $queryParams['oauth_verifier'] ?? $bodyParams['oauth_verifier'];
        }

        if (!empty($oauthVerifier)) {
            $defaultParams['oauth_verifier'] = $oauthVerifier;
        }

        $request = $this->createRequest(
            $this->accessTokenMethod,
            RequestUtil::composeUrl($this->accessTokenUrl, array_merge($defaultParams, $params))
        );

        $request = $this->signRequest($request, $requestToken);

        $request = $this->signRequest($request);
        $response = $this->sendRequest($request);

        $token = $this->createToken(
            [
                'setParams()' => [Json::decode($response->getBody()->getContents())],
            ]
        );
        $this->setAccessToken($token);

        return $token;
    }

    public function applyAccessTokenToRequest(RequestInterface $request, OAuthToken $accessToken): RequestInterface
    {
        $data = RequestUtil::getParams($request);
        $data['oauth_consumer_key'] = $this->consumerKey;
        $data['oauth_token'] = $accessToken->getToken();
        return RequestUtil::addParams($request, $data);
    }

    /**
     * Gets new auth token to replace expired one.
     *
     * @param OAuthToken|null $token expired auth token.
     *
     * @return OAuthToken new auth token.
     */
    public function refreshAccessToken(?OAuthToken $token = null): OAuthToken
    {
        // @todo
        return $token;
    }

    public function getConsumerKey(): string
    {
        return $this->consumerKey;
    }

    public function setConsumerKey(string $consumerKey): void
    {
        $this->consumerKey = $consumerKey;
    }

    public function getConsumerSecret(): string
    {
        return $this->consumerSecret;
    }

    public function setConsumerSecret(string $consumerSecret): void
    {
        $this->consumerSecret = $consumerSecret;
    }

    public function getRequestTokenUrl(): string
    {
        return $this->requestTokenUrl;
    }

    public function setRequestTokenUrl(string $requestTokenUrl): void
    {
        $this->requestTokenUrl = $requestTokenUrl;
    }

    public function getRequestTokenMethod(): string
    {
        return $this->requestTokenMethod;
    }

    public function setRequestTokenMethod(string $requestTokenMethod): void
    {
        $this->requestTokenMethod = $requestTokenMethod;
    }

    public function getAccessTokenUrl(): string
    {
        return $this->accessTokenUrl;
    }

    public function setAccessTokenUrl(string $accessTokenUrl): void
    {
        $this->accessTokenUrl = $accessTokenUrl;
    }

    public function getAccessTokenMethod(): string
    {
        return $this->accessTokenMethod;
    }

    public function setAccessTokenMethod(string $accessTokenMethod): void
    {
        $this->accessTokenMethod = $accessTokenMethod;
    }

    public function getAuthorizationHeaderMethods(): ?array
    {
        return $this->authorizationHeaderMethods;
    }

    public function setAuthorizationHeaderMethods(?array $authorizationHeaderMethods = null): void
    {
        $this->authorizationHeaderMethods = $authorizationHeaderMethods;
    }

    /**
     * Composes default {@see returnUrl} value.
     *
     * @return string return URL.
     */
    protected function defaultReturnUrl(ServerRequestInterface $request): string
    {
        $params = $request->getQueryParams();
        unset($params['oauth_token']);

        return (string)$request->getUri()->withQuery(http_build_query($params, '', '&', PHP_QUERY_RFC3986));
    }
}
