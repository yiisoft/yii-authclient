<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Client;

use Yiisoft\Yii\AuthClient\OAuth2;

/**
 * Google allows authentication via Google OAuth.
 *
 * In order to use Google OAuth you must create a project at <https://console.developers.google.com/project>
 * and setup its credentials at <https://console.developers.google.com/project/[yourProjectId]/apiui/credential>.
 * In order to enable using scopes for retrieving user attributes, you should also enable Google+ API at
 * <https://console.developers.google.com/project/[yourProjectId]/apiui/api/plus>
 *
 * @link https://console.developers.google.com/project
 */
class Google extends OAuth2
{
    protected string $authUrl = 'https://accounts.google.com/o/oauth2/auth';
    protected string $tokenUrl = 'https://accounts.google.com/o/oauth2/token';
    protected string $endpoint = 'https://www.googleapis.com/plus/v1';

    /**
     * @return string service name.
     */
    public function getName(): string
    {
        return 'google';
    }

    /**
     * @return string service title.
     */
    public function getTitle(): string
    {
        return 'Google';
    }

    protected function getDefaultScope(): string
    {
        return 'profile email';
    }

    protected function initUserAttributes(): array
    {
        return $this->api('people/me', 'GET');
    }
}
