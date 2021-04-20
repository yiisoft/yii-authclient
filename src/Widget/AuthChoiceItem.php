<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Widget;

use Yiisoft\Widget\Widget;
use Yiisoft\Yii\AuthClient\AuthClientInterface;

/**
 * AuthChoiceItem is a base class for creating widgets, which can be used to render link
 * for auth client at {@see AuthChoice}.
 */
abstract class AuthChoiceItem extends Widget
{
    /**
     * @var AuthClientInterface auth client instance.
     */
    public AuthClientInterface $client;
    /**
     * @var AuthChoice parent AuthChoice widget
     */
    public AuthChoice $authChoice;
}
