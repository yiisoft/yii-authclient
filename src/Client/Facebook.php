<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Client;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Yii\AuthClient\OAuth2;
use Yiisoft\Yii\AuthClient\OAuthToken;
use Yiisoft\Yii\AuthClient\RequestUtil;

/**
 * Facebook allows authentication via Facebook OAuth.
 *
 * In order to use Facebook OAuth you must register your application at <https://developers.facebook.com/apps>.
 *
 * Example application configuration:
 *
 * ```php
 * 'components' => [
 *     'authClientCollection' => [
 *         'class' => Yiisoft\Yii\AuthClient\Collection::class,
 *         'clients' => [
 *             'facebook' => [
 *                 'class' => Yiisoft\Yii\AuthClient\Clients\Facebook::class,
 *                 'clientId' => 'facebook_client_id',
 *                 'clientSecret' => 'facebook_client_secret',
 *             ],
 *         ],
 *     ]
 *     // ...
 * ]
 * ```
 *
 * @link https://developers.facebook.com/apps
 * @link http://developers.facebook.com/docs/reference/api
 */
final class Facebook extends OAuth2
{
    protected string $authUrl = 'https://www.facebook.com/dialog/oauth';
    protected string $tokenUrl = 'https://graph.facebook.com/oauth/access_token';
    protected string $endpoint = 'https://graph.facebook.com';
    /**
     * @var array list of attribute names, which should be requested from API to initialize user attributes.
     */
    private array $attributeNames = [
        'name',
        'email',
    ];
    protected bool $autoRefreshAccessToken = false; // Facebook does not provide access token refreshment
    /**
     * @var bool whether to automatically upgrade short-live (2 hours) access token to long-live (60 days) one, after fetching it.
     *
     * @see exchangeToken()
     */
    private bool $autoExchangeAccessToken = false;
    /**
     * @var string URL endpoint for the client auth code generation.
     *
     * @link https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
     * @see fetchClientAuthCode()
     * @see fetchClientAccessToken()
     */
    private string $clientAuthCodeUrl = 'https://graph.facebook.com/oauth/client_code';

    public function applyAccessTokenToRequest(RequestInterface $request, OAuthToken $accessToken): RequestInterface
    {
        $request = parent::applyAccessTokenToRequest($request, $accessToken);

        $params = [];
        if (($machineId = $accessToken->getParam('machine_id')) !== null) {
            $params['machine_id'] = $machineId;
        }
        $params['appsecret_proof'] = hash_hmac('sha256', $accessToken->getToken(), $this->clientSecret);
        return RequestUtil::addParams($request, $params);
    }

    public function fetchAccessToken(ServerRequestInterface $request, $authCode, array $params = []): OAuthToken
    {
        $token = parent::fetchAccessToken($request, $authCode, $params);
        if ($this->autoExchangeAccessToken) {
            $token = $this->exchangeAccessToken($token);
        }
        return $token;
    }

    /**
     * Exchanges short-live (2 hours) access token to long-live (60 days) one.
     * Note that this method will success for already long-live token, but will not actually prolong it any further.
     * Pay attention, that this method will fail on already expired access token.
     *
     * @link https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
     *
     * @param OAuthToken $token short-live access token.
     *
     * @return OAuthToken long-live access token.
     */
    public function exchangeAccessToken(OAuthToken $token): OAuthToken
    {
        $params = [
            'grant_type' => 'fb_exchange_token',
            'fb_exchange_token' => $token->getToken(),
        ];

        $request = $this->createRequest('POST', $this->getTokenUrl());
        //->setParams($params);
        $this->applyClientCredentialsToRequest($request);
        $response = $this->sendRequest($request);

        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);

        return $token;
    }

    /**
     * Requests the authorization code for the client-specific access token.
     * This make sense for the distributed applications, which provides several Auth clients (web and mobile)
     * to avoid triggering Facebook's automated spam systems.
     *
     * @link https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
     * @see fetchClientAccessToken()
     *
     * @param ServerRequestInterface $incomingRequest
     * @param OAuthToken|null $token access token, if not set {@see accessToken} will be used.
     * @param array $params additional request params.
     *
     * @return string client auth code.
     */
    public function fetchClientAuthCode(
        ServerRequestInterface $incomingRequest,
        OAuthToken $token = null,
        $params = []
    ): string {
        if ($token === null) {
            $token = $this->getAccessToken();
        }

        $params = array_merge(
            [
                'access_token' => $token->getToken(),
                'redirect_uri' => $this->getReturnUrl($incomingRequest),
            ],
            $params
        );

        $request = $this->createRequest('POST', $this->clientAuthCodeUrl);
        $request = RequestUtil::addParams($request, $params);

        $request = $this->applyClientCredentialsToRequest($request);

        $response = $this->sendRequest($request);

        // TODO: parse response!

        return $response['code'];
    }

    /**
     * Fetches access token from client-specific authorization code.
     * This make sense for the distributed applications, which provides several Auth clients (web and mobile)
     * to avoid triggering Facebook's automated spam systems.
     *
     * @link https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
     * @see fetchClientAuthCode()
     *
     * @param ServerRequestInterface $incomingRequest
     * @param string $authCode client auth code.
     * @param array $params
     *
     * @return OAuthToken long-live client-specific access token.
     */
    public function fetchClientAccessToken(
        ServerRequestInterface $incomingRequest,
        string $authCode,
        array $params = []
    ): OAuthToken {
        $params = array_merge(
            [
                'code' => $authCode,
                'redirect_uri' => $this->getReturnUrl($incomingRequest),
                'client_id' => $this->clientId,
            ],
            $params
        );

        $request = $this->createRequest('POST', $this->getTokenUrl());
        $request = RequestUtil::addParams($request, $params);

        $response = $this->sendRequest($request);

        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);

        return $token;
    }

    /**
     * @return string service name.
     */
    public function getName(): string
    {
        return 'facebook';
    }

    /**
     * @return string service title.
     */
    public function getTitle(): string
    {
        return 'Facebook';
    }

    protected function initUserAttributes(): array
    {
        return $this->api(
            'me',
            'GET',
            [
                'fields' => implode(',', $this->attributeNames),
            ]
        );
    }

    protected function defaultViewOptions(): array
    {
        return [
            'popupWidth' => 860,
            'popupHeight' => 480,
        ];
    }

    protected function getDefaultScope(): string
    {
        return 'email';
    }
}
