<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Client;

use Psr\Http\Message\RequestInterface;
use RuntimeException;
use Yiisoft\Json\Json;
use Yiisoft\Yii\AuthClient\OAuth2;
use Yiisoft\Yii\AuthClient\OAuthToken;
use Yiisoft\Yii\AuthClient\RequestUtil;

/**
 * VKontakte allows authentication via VKontakte OAuth.
 *
 * In order to use VKontakte OAuth you must register your application at <http://vk.com/editapp?act=create>.
 *
 * @link http://vk.com/editapp?act=create
 * @link http://vk.com/developers.php?oid=-1&p=users.get
 */
final class VKontakte extends OAuth2
{
    protected string $authUrl = 'https://oauth.vk.com/authorize';
    protected string $tokenUrl = 'https://oauth.vk.com/access_token';
    protected string $endpoint = 'https://api.vk.com/method';
    /**
     * @var array list of attribute names, which should be requested from API to initialize user attributes.
     */
    private array $attributeNames = [
        'uid',
        'first_name',
        'last_name',
        'nickname',
        'screen_name',
        'sex',
        'bdate',
        'city',
        'country',
        'timezone',
        'photo',
    ];
    /**
     * @var string the API version to send in the API request.
     *
     * @see https://vk.com/dev/versions
     */
    private string $apiVersion = '3.0';

    public function applyAccessTokenToRequest(RequestInterface $request, OAuthToken $accessToken): RequestInterface
    {
        return RequestUtil::addParams(
            $request,
            [
                'v' => $this->apiVersion,
                'uids' => $accessToken->getParam('user_id'),
                'access_token' => $accessToken->getToken(),
            ]
        );
    }

    /**
     * @return string service name.
     */
    public function getName(): string
    {
        return 'vkontakte';
    }

    /**
     * @return string service title.
     */
    public function getTitle(): string
    {
        return 'VKontakte';
    }

    protected function initUserAttributes(): array
    {
        $response = $this->api(
            'users.get.json',
            'GET',
            [
                'fields' => implode(',', $this->attributeNames),
            ]
        );

        if (empty($response['response'])) {
            throw new RuntimeException(
                'Unable to init user attributes due to unexpected response: ' . Json::encode($response)
            );
        }

        $attributes = array_shift($response['response']);

        $accessToken = $this->getAccessToken();
        if (is_object($accessToken)) {
            $accessTokenParams = $accessToken->getParams();
            unset($accessTokenParams['access_token'], $accessTokenParams['expires_in']);
            $attributes = array_merge($accessTokenParams, $attributes);
        }

        return $attributes;
    }

    protected function defaultNormalizeUserAttributeMap(): array
    {
        return [
            'id' => 'uid',
        ];
    }
}
