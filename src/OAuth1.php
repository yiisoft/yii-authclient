<?php
/**
 * @link http://www.yiiframework.com/
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Yii\AuthClient;

use Psr\Http\Message\RequestInterface;
use yii\base\InvalidArgumentException;
use yii\helpers\Yii;
use yii\web\HttpException;

/**
 * OAuth1 serves as a client for the OAuth 1/1.0a flow.
 *
 * In order to acquire access token perform following sequence:
 *
 * ```php
 * use Yiisoft\Yii\AuthClient\OAuth1;
 * use yii\helpers\Yii;
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
 * https://tools.ietf.org/html/rfc5849
 *
 * @author Paul Klimov <klimov.paul@gmail.com>
 * @since 2.0
 */
abstract class OAuth1 extends BaseOAuth
{
    private const PROTOCOL_VERSION = '1.0';

    /**
     * @var string OAuth consumer key.
     */
    public $consumerKey;
    /**
     * @var string OAuth consumer secret.
     */
    public $consumerSecret;
    /**
     * @var string OAuth request token URL.
     */
    public $requestTokenUrl;
    /**
     * @var string request token HTTP method.
     */
    public $requestTokenMethod = 'GET';
    /**
     * @var string OAuth access token URL.
     */
    public $accessTokenUrl;
    /**
     * @var string access token HTTP method.
     */
    public $accessTokenMethod = 'GET';
    /**
     * @var array|null list of the request methods, which require adding 'Authorization' header.
     * By default only POST requests will have 'Authorization' header.
     * You may set this option to `null` in order to make all requests to use 'Authorization' header.
     * @since 2.1.1
     */
    public $authorizationHeaderMethods = ['POST'];


    /**
     * Fetches the OAuth request token.
     * @param array $params additional request params.
     * @return OAuthToken request token.
     */
    public function fetchRequestToken(array $params = [])
    {
        $this->setAccessToken(null);
        $defaultParams = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_callback' => $this->getReturnUrl(),
            //'xoauth_displayname' => Yii::getApp()->name,
        ];
        if (!empty($this->getScope())) {
            $defaultParams['scope'] = $this->getScope();
        }

        $request = $this->createRequest($this->requestTokenMethod, $this->requestTokenUrl . '?' . http_build_query(array_merge($defaultParams, $params)));

        $request = $this->signRequest($request);
        $response = $this->sendRequest($request);

        $token = $this->createToken([
            'params' => $response
        ]);
        $this->setState('requestToken', $token);

        return $token;
    }

    /**
     * Composes user authorization URL.
     * @param OAuthToken $requestToken OAuth request token.
     * @param array $params additional request params.
     * @return string authorize URL
     * @throws InvalidArgumentException on failure.
     */
    public function buildAuthUrl(OAuthToken $requestToken = null, array $params = [])
    {
        if (!is_object($requestToken)) {
            $requestToken = $this->getState('requestToken');
            if (!is_object($requestToken)) {
                throw new InvalidArgumentException('Request token is required to build authorize URL!');
            }
        }
        $params['oauth_token'] = $requestToken->getToken();

        return $this->composeUrl($this->authUrl, $params);
    }

    /**
     * Fetches OAuth access token.
     * @param string $oauthToken OAuth token returned with redirection back to client.
     * @param OAuthToken $requestToken OAuth request token.
     * @param string $oauthVerifier OAuth verifier.
     * @param array $params additional request params.
     * @return OAuthToken OAuth access token.
     * @throws InvalidArgumentException on failure.
     * @throws HttpException in case oauth token miss-matches request token.
     */
    public function fetchAccessToken($oauthToken = null, OAuthToken $requestToken = null, $oauthVerifier = null, array $params = [])
    {
        $incomingRequest = Yii::getApp()->getRequest();

        if ($oauthToken === null) {
            $oauthToken = $incomingRequest->get('oauth_token', $incomingRequest->post('oauth_token', $oauthToken));
        }

        if (!is_object($requestToken)) {
            $requestToken = $this->getState('requestToken');
            if (!is_object($requestToken)) {
                throw new InvalidArgumentException('Request token is required to fetch access token!');
            }
        }

        if (strcmp($requestToken->getToken(), $oauthToken) !== 0) {
            throw new HttpException(400, 'Invalid auth state parameter.');
        }

        $this->removeState('requestToken');

        $defaultParams = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_token' => $requestToken->getToken()
        ];
        if ($oauthVerifier === null) {
            $oauthVerifier = $incomingRequest->get('oauth_verifier', $incomingRequest->post('oauth_verifier'));
        }
        if (!empty($oauthVerifier)) {
            $defaultParams['oauth_verifier'] = $oauthVerifier;
        }

        $request = $this->createRequest($this->accessTokenMethod, $this->composeUrl($this->accessTokenUrl, array_merge($defaultParams, $params)));

        $request = $this->signRequest($request, $requestToken);

        $request = $this->signRequest($request);
        $response = $this->sendRequest($request);

        $token = $this->createToken([
            'params' => $response
        ]);
        $this->setAccessToken($token);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function applyAccessTokenToRequest(RequestInterface $request, OAuthToken $accessToken): RequestInterface
    {
        $data = RequestUtil::getParams($request);
        $data['oauth_consumer_key'] = $this->consumerKey;
        $data['oauth_token'] = $accessToken->getToken();
        return RequestUtil::addParams($request, $data);
    }

    /**
     * Gets new auth token to replace expired one.
     * @param OAuthToken $token expired auth token.
     * @return OAuthToken new auth token.
     */
    public function refreshAccessToken(OAuthToken $token)
    {
        // @todo
        return null;
    }

    /**
     * Composes default [[returnUrl]] value.
     * @return string return URL.
     */
    protected function defaultReturnUrl()
    {
        $params = Yii::getApp()->getRequest()->getQueryParams();
        unset($params['oauth_token']);
        $params[0] = Yii::getApp()->controller->getRoute();

        return Yii::getApp()->getUrlManager()->createAbsoluteUrl($params);
    }

    /**
     * Generates nonce value.
     * @return string nonce value.
     */
    protected function generateNonce()
    {
        return md5(microtime() . mt_rand());
    }

    /**
     * Generates timestamp.
     * @return int timestamp.
     */
    protected function generateTimestamp()
    {
        return time();
    }

    /**
     * Generate common request params like version, timestamp etc.
     * @return array common request params.
     */
    protected function generateCommonRequestParams()
    {
        $params = [
            'oauth_version' => self::PROTOCOL_VERSION,
            'oauth_nonce' => $this->generateNonce(),
            'oauth_timestamp' => $this->generateTimestamp(),
        ];

        return $params;
    }

    /**
     * Sign given request with [[signatureMethod]].
     * @param RequestInterface $request request instance.
     * @param OAuthToken|null $token OAuth token to be used for signature, if not set [[accessToken]] will be used.
     * @since 2.1 this method is public.
     */
    public function signRequest(RequestInterface $request, $token = null): RequestInterface
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

        $url = $request->getUri()->__toString();

        $signatureMethod = $this->getSignatureMethod();

        $params['oauth_signature_method'] = $signatureMethod->getName();
        $signatureBaseString = $this->composeSignatureBaseString($request->getMethod(), $url, $params);
        $signatureKey = $this->composeSignatureKey($token);
        $params['oauth_signature'] = $signatureMethod->generateSignature($signatureBaseString, $signatureKey);

        if ($this->authorizationHeaderMethods === null || in_array(strtoupper($request->getMethod()), array_map('strtoupper', $this->authorizationHeaderMethods), true)) {
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
     * Creates signature base string, which will be signed by [[signatureMethod]].
     * @param string $method request method.
     * @param string $url request URL.
     * @param array $params request params.
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
        uksort($params, 'strcmp'); // Parameters are sorted by name, using lexicographical byte value ordering. Ref: Spec: 9.1.1
        $parts = [
            strtoupper($method),
            $url,
            http_build_query($params, '', '&', PHP_QUERY_RFC3986)
        ];
        $parts = array_map('rawurlencode', $parts);

        return implode('&', $parts);
    }

    /**
     * Composes request signature key.
     * @param OAuthToken|null $token OAuth token to be used for signature key.
     * @return string signature key.
     */
    protected function composeSignatureKey($token = null)
    {
        $signatureKeyParts = [
            $this->consumerSecret
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
     * @param array $params request params.
     * @param string $realm authorization realm.
     * @return array authorization header in format: [name => content].
     */
    protected function composeAuthorizationHeader(array $params, $realm = '')
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
            $headerParams[] = rawurlencode($key) . '="' . rawurlencode($value) . '"';
        }
        if (!empty($headerParams)) {
            $header .= ' ' . implode(', ', $headerParams);
        }

        return ['Authorization' => $header];
    }
}
