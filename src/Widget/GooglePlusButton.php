<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Widget;

use Yiisoft\Html\Html;
use Yiisoft\View\WebView;
use Yiisoft\Yii\AuthClient\Client\GoogleHybrid;
use Yiisoft\Yii\AuthClient\Exception\InvalidConfigException;

/**
 * GooglePlusButton renders Google+ sign-in button.
 * This widget is designed to interact with {@see GoogleHybrid}.
 *
 * @see GoogleHybrid
 * @link https://developers.google.com/+/web/signin/
 *
 * @property string $callback Callback JavaScript function name. Note that the type of this property differs
 * in getter and setter. See {@see getCallback()} and {@see setCallback()} for details.
 */
class GooglePlusButton extends AuthChoiceItem
{
    /**
     * @var array button tag HTML options, which will be merged with the default ones.
     */
    public array $buttonHtmlOptions = [];

    /**
     * @var array|string name of the JavaScript function, which should be used as sign-in callback.
     * If blank default one will be generated: it will redirect page to the auth action using auth result
     * as GET parameters.
     * You may pass an array configuration of the URL here, which will be used creating such
     * default callback.
     */
    private $callback;

    /**
     * Initializes the widget.
     */
    public function init()
    {
        if (!($this->client instanceof GoogleHybrid)) {
            throw new InvalidConfigException(
                '"' . static::class . '::$client" must be instance of "' . GoogleHybrid::class . '". "'
                . get_class($this->client) . '" given.'
            );
        }
    }

    /**
     * Runs the widget.
     */
    public function run(): string
    {
        $this->registerClientScript();
        return $this->renderButton();
    }

    /**
     * Registers necessary JavaScript.
     */
    protected function registerClientScript()
    {
        $js = <<<JS
        (function() {
            var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;
            po.src = 'https://apis.google.com/js/client:plusone.js';
            var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(po, s);
        })();
        JS;
        $this->view->registerJs($js, WebView::POSITION_END, __CLASS__);
    }

    /**
     * Renders sign-in button.
     *
     * @return string button HTML.
     */
    protected function renderButton()
    {
        $buttonHtmlOptions = array_merge(
            [
                'class' => 'g-signin',
                'data-callback' => $this->getCallback(),
                'data-clientid' => $this->client->getClientId(),
                'data-cookiepolicy' => 'single_host_origin',
                'data-requestvisibleactions' => null,
                'data-scope' => $this->client->scope,
                'data-accesstype' => 'offline',
                'data-width' => 'iconOnly',
            ],
            $this->buttonHtmlOptions
        );
        return Html::tag('span', Html::tag('span', '', $buttonHtmlOptions), ['id' => 'signinButton']);
    }

    /**
     * @return string callback JavaScript function name.
     */
    public function getCallback()
    {
        if (empty($this->callback)) {
            $this->callback = $this->generateCallback();
        } elseif (is_array($this->callback)) {
            $this->callback = $this->generateCallback($this->callback);
        }
        return $this->callback;
    }

    /**
     * @param array|string $callback callback JavaScript function name or URL config.
     */
    public function setCallback($callback): void
    {
        $this->callback = $callback;
    }

    /**
     * Generates JavaScript callback function, which will be used to handle auth response.
     *
     * @param array $url auth callback URL.
     *
     * @return string JavaScript function name.
     */
    protected function generateCallback(array $url = []): string
    {
        if (empty($url)) {
            $url = $this->authChoice->createClientUrl($this->client);
        } else {
            $url = Url::to($url);
        }
        if (strpos($url, '?') === false) {
            $url .= '?';
        } else {
            $url .= '&';
        }

        $callbackName = 'googleSignInCallback' . md5($this->id);
        $js = <<<JS
        function $callbackName(authResult); {
            var urlParams = [];

            if (authResult['code']) {
                urlParams.push('code=' + encodeURIComponent(authResult['code']));
            } else if (authResult['error']) {
                if (authResult['error'] == 'immediate_failed') {
                    return;
                }
                urlParams.push('error=' + encodeURIComponent(authResult['error']));
                urlParams.push('error_description=' + encodeURIComponent(authResult['error_description']));
            } else {
                for (var propName in authResult) {
                    var propValue = authResult[propName];
                    if (typeof propValue != 'object') {
                        urlParams.push(encodeURIComponent(propName) + '=' + encodeURIComponent(propValue));
                    }
                }
            }

            window.location = '$url' + urlParams.join('&');
        }
        JS;
        $this->view->registerJs($js, WebView::POSITION_END, __CLASS__ . '#' . $this->id);

        return $callbackName;
    }
}
