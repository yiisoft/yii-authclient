<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Client;

use Psr\Http\Message\RequestInterface;
use Yiisoft\Yii\AuthClient\OAuth2;
use Yiisoft\Yii\AuthClient\OAuthToken;
use Yiisoft\Yii\AuthClient\RequestUtil;

/**
 * LinkedIn allows authentication via LinkedIn OAuth.
 *
 * In order to use linkedIn OAuth you must register your application at <https://www.linkedin.com/secure/developer>.
 *
 * @link https://developer.linkedin.com/docs/oauth2
 * @link https://www.linkedin.com/secure/developer
 * @link https://developer.linkedin.com/docs/rest-api
 */
final class LinkedIn extends OAuth2
{
    protected string $authUrl = 'https://www.linkedin.com/oauth/v2/authorization';
    protected string $tokenUrl = 'https://www.linkedin.com/oauth/v2/accessToken';
    protected string $endpoint = 'https://api.linkedin.com/v1';
    /**
     * @var array list of attribute names, which should be requested from API to initialize user attributes.
     */
    private array $attributeNames = [
        'id',
        'email-address',
        'first-name',
        'last-name',
        'public-profile-url',
    ];

    public function applyAccessTokenToRequest(RequestInterface $request, OAuthToken $accessToken): RequestInterface
    {
        return RequestUtil::addParams(
            $request,
            [
                'oauth2_access_token' => $accessToken->getToken(),
            ]
        );
    }

    /**
     * @return string service name.
     */
    public function getName(): string
    {
        return 'linkedin';
    }

    /**
     * @return string service title.
     */
    public function getTitle(): string
    {
        return 'LinkedIn';
    }

    protected function getDefaultScope(): string
    {
        return 'r_basicprofile r_emailaddress';
    }

    protected function defaultNormalizeUserAttributeMap(): array
    {
        return [
            'email' => 'email-address',
            'first_name' => 'first-name',
            'last_name' => 'last-name',
        ];
    }

    protected function initUserAttributes(): array
    {
        return $this->api('people/~:(' . implode(',', $this->attributeNames) . ')', 'GET');
    }
}
