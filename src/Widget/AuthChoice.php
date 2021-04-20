<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient\Widget;

use Yiisoft\Assets\AssetManager;
use Yiisoft\Html\Html;
use Yiisoft\Html\NoEncodeStringableInterface;
use Yiisoft\Html\Tag\A;
use Yiisoft\Json\Json;
use Yiisoft\Router\UrlGeneratorInterface;
use Yiisoft\View\WebView;
use Yiisoft\Widget\Widget;
use Yiisoft\Yii\AuthClient\Asset\AuthChoiceAsset;
use Yiisoft\Yii\AuthClient\Asset\AuthChoiceStyleAsset;
use Yiisoft\Yii\AuthClient\AuthClientInterface;
use Yiisoft\Yii\AuthClient\Collection;
use Yiisoft\Yii\AuthClient\Exception\InvalidConfigException;

/**
 * AuthChoice prints buttons for authentication via various auth clients.
 * It opens a popup window for the client authentication process.
 * By default this widget relies on presence of {@see \Yiisoft\Yii\AuthClient\Collection} among application components
 * to get auth clients information.
 *
 * Example:
 *
 * ```php
 * <?= AuthChoice::widget()->authRoute('site/auth'); ?>
 * ```
 *
 * You can customize the widget appearance by using {@see begin()} and {@see end()} syntax
 * along with using method {@see clientLink()} or {@see createClientUrl()}.
 * For example:
 *
 * ```php
 * <?php
 * use Yiisoft\Yii\AuthClient\Widget\AuthChoice;
 * ?>
 * <?php $authChoice = AuthChoice::begin([
 *     'baseAuthUrl' => ['site/auth']
 * ]); ?>
 * <ul>
 * <?php foreach ($authChoice->getClients() as $client): ?>
 *     <li><?= $authChoice->clientLink($client) ?></li>
 * <?php endforeach; ?>
 * </ul>
 * <?php AuthChoice::end(); ?>
 * ```
 *
 * This widget supports following keys for {@see AuthClientInterface::getViewOptions()} result:
 *
 *  - popupWidth: int, width of the popup window in pixels.
 *  - popupHeight: int, height of the popup window in pixels.
 *  - widget: array, configuration for the widget, which should be used to render a client link;
 *    such widget should be a subclass of {@see AuthChoiceItem}.
 *
 * @see \Yiisoft\Yii\AuthClient\AuthAction
 */
final class AuthChoice extends Widget
{
    /**
     * @var string name of the GET param , which should be used to passed auth client id to URL
     * defined by {@see baseAuthUrl}.
     */
    private string $clientIdGetParamName = 'authclient';
    /**
     * @var array the HTML attributes that should be rendered in the div HTML tag representing the container element.
     *
     * @see Html::renderTagAttributes() for details on how attributes are being rendered.
     */
    private array $options = [];
    /**
     * @var array additional options to be passed to the underlying JS plugin.
     */
    private array $clientOptions = [];
    /**
     * @var bool indicates if popup window should be used instead of direct links.
     */
    private bool $popupMode = true;
    /**
     * @var bool indicates if widget content, should be rendered automatically.
     * Note: this value automatically set to 'false' at the first call of {@see createClientUrl()}
     */
    private bool $autoRender = true;

    /**
     * @var string route name for the external clients authentication URL.
     */
    private string $authRoute;
    /**
     * @var AuthClientInterface[] auth providers list.
     */
    private array $clients;
    private UrlGeneratorInterface $urlGenerator;
    private WebView $webView;
    private AssetManager $assetManager;

    public function __construct(
        Collection $clientCollection,
        UrlGeneratorInterface $urlGenerator,
        WebView $webView,
        AssetManager $assetManager
    ) {
        $this->clients = $clientCollection->getClients();
        $this->urlGenerator = $urlGenerator;
        $this->webView = $webView;
        $this->assetManager = $assetManager;
        $this->init();
    }

    /**
     * Initializes the widget.
     */
    public function init(): void
    {
        if ($this->popupMode) {
            $this->assetManager->register(
                [
                    AuthChoiceAsset::class,
                ]
            );
            if (empty($this->clientOptions)) {
                $options = '';
            } else {
                $options = Json::htmlEncode($this->clientOptions);
            }
            $this->webView->registerJs("jQuery('#" . $this->getId() . "').authchoice({$options});");
        } else {
            $this->assetManager->register(
                [
                    AuthChoiceStyleAsset::class,
                ]
            );
        }
        $this->options['id'] = $this->getId();
        echo Html::openTag('div', $this->options);
    }

    public function getId(): string
    {
        return 'yii-auth-client';
    }

    /**
     * Runs the widget.
     *
     * @throws \Yiisoft\Factory\Exception\InvalidConfigException
     *
     * @return string rendered HTML.
     */
    public function run(): string
    {
        $content = '';
        if ($this->autoRender) {
            $content .= $this->renderMainContent();
        }
        $content .= Html::closeTag('div');
        return $content;
    }

    /**
     * Renders the main content, which includes all external services links.
     *
     * @throws InvalidConfigException
     * @throws \Yiisoft\Factory\Exception\InvalidConfigException
     *
     * @return string generated HTML.
     */
    protected function renderMainContent(): string
    {
        $ul = Html::tag('ul', '', ['class' => 'auth-clients']);
        foreach ($this->getClients() as $externalService) {
            $ul = $ul->addContent(Html::tag('li')->content($this->clientLink($externalService)));
        }
        return $ul->render();
    }

    /**
     * @return AuthClientInterface[] auth providers
     */
    public function getClients(): array
    {
        return $this->clients;
    }

    /**
     * @param AuthClientInterface[] $clients auth providers
     */
    public function setClients(array $clients): void
    {
        $this->clients = $clients;
    }

    /**
     * Outputs client auth link.
     *
     * @param AuthClientInterface $client external auth client instance.
     * @param string|null $text link text, if not set - default value will be generated.
     * @param array $htmlOptions link HTML options.
     *
     * @throws InvalidConfigException on wrong configuration.
     * @throws \Yiisoft\Factory\Exception\InvalidConfigException
     *
     * @return NoEncodeStringableInterface generated HTML.
     */
    public function clientLink(AuthClientInterface $client, string $text = null, array $htmlOptions = []): NoEncodeStringableInterface
    {
        $viewOptions = $client->getViewOptions();

        if (empty($viewOptions['widget'])) {
            if ($text === null) {
                $text = Html::tag('span', '', ['class' => 'auth-icon ' . $client->getName()]);
            }
            if (!isset($htmlOptions['class'])) {
                $htmlOptions['class'] = $client->getName();
            }
            if (!isset($htmlOptions['title'])) {
                $htmlOptions['title'] = $client->getTitle();
            }
            Html::addCssClass($htmlOptions, ['widget' => 'auth-link']);

            if ($this->popupMode) {
                if (isset($viewOptions['popupWidth'])) {
                    $htmlOptions['data-popup-width'] = $viewOptions['popupWidth'];
                }
                if (isset($viewOptions['popupHeight'])) {
                    $htmlOptions['data-popup-height'] = $viewOptions['popupHeight'];
                }
            }
            return Html::a('', $this->createClientUrl($client), $htmlOptions)->content($text);
        }

        $widgetConfig = $viewOptions['widget'];
        if (!isset($widgetConfig['class'])) {
            throw new InvalidConfigException('Widget config "class" parameter is missing');
        }
        /* @var $widgetClass Widget */
        $widgetClass = $widgetConfig['class'];
        if (!(is_subclass_of($widgetClass, AuthChoiceItem::class))) {
            throw new InvalidConfigException('Item widget class must be subclass of "' . AuthChoiceItem::class . '"');
        }
        unset($widgetConfig['class']);
        $widgetConfig['client'] = $client;
        $widgetConfig['authChoice'] = $this;
        return new class($widgetClass::widget($widgetConfig)->render()) implements NoEncodeStringableInterface {
            private string $string;

            public function __construct(string $string) {
                $this->string = $string;
            }

            public function __toString(): string
            {
                return $this->string;
            }
        };
    }

    /**
     * Composes client auth URL.
     *
     * @param AuthClientInterface $client external auth client instance.
     *
     * @return string auth URL.
     */
    public function createClientUrl($client): string
    {
        $this->autoRender = false;
        $params = [];
        $params[$this->clientIdGetParamName] = $client->getName();

        return $this->urlGenerator->generate($this->authRoute, $params);
    }

    /**
     * @param string $authRoute
     *
     * @return self
     */
    public function authRoute(string $authRoute): self
    {
        $this->authRoute = $authRoute;
        return $this;
    }
}
