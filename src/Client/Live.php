<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Client;

use Yiisoft\Yii\AuthClient\OAuth2;

/**
 * Live allows authentication via Microsoft Live OAuth.
 *
 * In order to use Microsoft Live OAuth you must register your application at <https://account.live.com/developers/applications>
 *
 * @see https://account.live.com/developers/applications
 * @see http://msdn.microsoft.com/en-us/library/live/hh243647.aspx
 */
final class Live extends OAuth2
{
    protected string $authUrl = 'https://login.live.com/oauth20_authorize.srf';
    protected string $tokenUrl = 'https://login.live.com/oauth20_token.srf';
    protected string $endpoint = 'https://apis.live.net/v5.0';

    /**
     * @return string service name.
     */
    public function getName(): string
    {
        return 'live';
    }

    /**
     * @return string service title.
     */
    public function getTitle(): string
    {
        return 'Live';
    }

    protected function getDefaultScope(): string
    {
        return 'wl.basic wl.emails';
    }

    protected function initUserAttributes(): array
    {
        return $this->api('me', 'GET');
    }
}
