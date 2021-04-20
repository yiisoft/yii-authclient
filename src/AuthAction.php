<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient;

use Exception;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;
use Yiisoft\Aliases\Aliases;
use Yiisoft\Http\Status;
use Yiisoft\View\Exception\ViewNotFoundException;
use Yiisoft\View\WebView;
use Yiisoft\Yii\AuthClient\Exception\InvalidConfigException;
use Yiisoft\Yii\AuthClient\Exception\NotSupportedException;

/**
 * AuthAction performs authentication via different auth clients.
 * It supports {@see OpenId}, {@see OAuth1} and {@see OAuth2} client types.
 *
 * Usage:
 *
 * ```php
 * class SiteController extends Controller
 * {
 *     public function actions()
 *     {
 *         return [
 *             'auth' => [
 *                 'class' => \Yiisoft\Yii\AuthClient\AuthAction::class,
 *                 'successCallback' => [$this, 'successCallback'],
 *             ],
 *         ]
 *     }
 *
 *     public function successCallback($client)
 *     {
 *         $attributes = $client->getUserAttributes();
 *         // user login or signup comes here
 *     }
 * }
 * ```
 *
 * Usually authentication via external services is performed inside the popup window.
 * This action handles the redirection and closing of popup window correctly.
 *
 * @see Collection
 * @see \Yiisoft\Yii\AuthClient\Widget\AuthChoice
 */
final class AuthAction implements MiddlewareInterface
{
    public const AUTH_NAME = 'auth_displayname';
    /**
     * @var Collection
     * It should point to {@see Collection} instance.
     */
    private Collection $clientCollection;
    /**
     * @var string name of the GET param, which is used to passed auth client id to this action.
     * Note: watch for the naming, make sure you do not choose name used in some auth protocol.
     */
    private string $clientIdGetParamName = 'authclient';
    /**
     * @var callable PHP callback, which should be triggered in case of successful authentication.
     * This callback should accept {@see AuthClientInterface} instance as an argument.
     * For example:
     *
     * ```php
     * public function onAuthSuccess(ClientInterface $client)
     * {
     *     $attributes = $client->getUserAttributes();
     *     // user login or signup comes here
     * }
     * ```
     *
     * If this callback returns {@see ResponseInterface} instance, it will be used as action response,
     * otherwise redirection to {@see successUrl} will be performed.
     */
    private $successCallback;
    /**
     * @var callable PHP callback, which should be triggered in case of authentication cancellation.
     * This callback should accept {@see AuthClientInterface} instance as an argument.
     * For example:
     *
     * ```php
     * public function onAuthCancel(ClientInterface $client)
     * {
     *     // set flash, logging, etc.
     * }
     * ```
     *
     * If this callback returns {@see ResponseInterface} instance, it will be used as action response,
     * otherwise redirection to {@see cancelUrl} will be performed.
     */
    private $cancelCallback;
    /**
     * @var string name or alias of the view file, which should be rendered in order to perform redirection.
     * If not set - default one will be used.
     */
    private string $redirectView;

    /**
     * @var string the redirect url after successful authorization.
     */
    private string $successUrl;
    /**
     * @var string the redirect url after unsuccessful authorization (e.g. user canceled).
     */
    private string $cancelUrl;
    private ResponseFactoryInterface $responseFactory;
    private Aliases $aliases;
    private WebView $view;

    public function __construct(
        Collection $clientCollection,
        Aliases $aliases,
        WebView $view,
        ResponseFactoryInterface $responseFactory
    ) {
        $this->clientCollection = $clientCollection;
        $this->responseFactory = $responseFactory;
        $this->aliases = $aliases;
        $this->view = $view;
    }

    /**
     * @param string $url successful URL.
     *
     * @return AuthAction
     */
    public function withSuccessUrl(string $url): self
    {
        $new = clone $this;
        $new->successUrl = $url;
        return $new;
    }

    /**
     * @param string $url cancel URL.
     *
     * @return AuthAction
     */
    public function withCancelUrl(string $url): self
    {
        $new = clone $this;
        $new->cancelUrl = $url;
        return $new;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $clientId = $request->getAttribute($this->clientIdGetParamName);
        if (!empty($clientId)) {
            if (!$this->clientCollection->hasClient($clientId)) {
                return $this->responseFactory->createResponse(Status::NOT_FOUND, "Unknown auth client '{$clientId}'");
            }
            $client = $this->clientCollection->getClient($clientId);

            return $this->auth($client, $request);
        }

        return $this->responseFactory->createResponse(Status::NOT_FOUND);
    }

    /**
     * Perform authentication for the given client.
     *
     * @param mixed $client auth client instance.
     * @param ServerRequestInterface $request
     *
     * @throws InvalidConfigException
     * @throws NotSupportedException on invalid client.
     * @throws Throwable
     * @throws ViewNotFoundException
     * @throws \Yiisoft\Factory\Exception\InvalidConfigException
     *
     * @return ResponseInterface response instance.
     */
    private function auth(AuthClientInterface $client, ServerRequestInterface $request): ResponseInterface
    {
        if ($client instanceof OAuth2) {
            return $this->authOAuth2($client, $request);
        }

        if ($client instanceof OAuth1) {
            return $this->authOAuth1($client, $request);
        }

        if ($client instanceof OpenId) {
            return $this->authOpenId($client, $request);
        }

        throw new NotSupportedException('Provider "' . get_class($client) . '" is not supported.');
    }

    /**
     * Performs OAuth2 auth flow.
     *
     * @param OAuth2 $client auth client instance.
     * @param ServerRequestInterface $request
     *
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws ViewNotFoundException
     *
     * @return ResponseInterface action response.
     */
    private function authOAuth2(OAuth2 $client, ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();

        if (isset($queryParams['error']) && ($error = $queryParams['error']) !== null) {
            if ($error === 'access_denied') {
                // user denied error
                return $this->authCancel($client);
            }
            // request error
            $errorMessage = $queryParams['error_description'] ?? $queryParams['error_message'] ?? null;
            if ($errorMessage === null) {
                $errorMessage = http_build_query($queryParams);
            }
            throw new Exception('Auth error: ' . $errorMessage);
        }

        // Get the access_token and save them to the session.
        if (isset($queryParams['code']) && ($code = $queryParams['code']) !== null) {
            $token = $client->fetchAccessToken($request, $code);
            if (!empty($token->getToken())) {
                return $this->authSuccess($client);
            }
            return $this->authCancel($client);
        }

        $url = $client->buildAuthUrl($request);
        return $this->responseFactory
            ->createResponse(Status::MOVED_PERMANENTLY)
            ->withHeader('Location', $url);
    }

    /**
     * This method is invoked in case of authentication cancellation.
     *
     * @param AuthClientInterface $client auth client instance.
     *
     * @throws Throwable
     * @throws ViewNotFoundException
     *
     * @return ResponseInterface response instance.
     */
    private function authCancel(AuthClientInterface $client): ResponseInterface
    {
        if (!is_callable($this->cancelCallback)) {
            throw new InvalidConfigException(
                '"' . self::class . '::$successCallback" should be a valid callback.'
            );
        }

        $response = ($this->cancelCallback)($client);
        if ($response instanceof ResponseInterface) {
            return $response;
        }

        return $this->redirectCancel();
    }

    /**
     * Redirect to the {@see cancelUrl} or simply close the popup window.
     *
     * @param string|null $url URL to redirect.
     *
     * @throws Throwable
     * @throws ViewNotFoundException
     *
     * @return ResponseInterface response instance.
     */
    private function redirectCancel(?string $url = null): ResponseInterface
    {
        if ($url === null) {
            $url = $this->cancelUrl;
        }
        return $this->redirect($url, false);
    }

    /**
     * Redirect to the given URL or simply close the popup window.
     *
     * @param string $url URL to redirect, could be a string or array config to generate a valid URL.
     * @param bool $enforceRedirect indicates if redirect should be performed even in case of popup window.
     *
     * @throws Throwable
     * @throws ViewNotFoundException
     *
     * @return ResponseInterface response instance.
     */
    private function redirect(string $url, bool $enforceRedirect = true): ResponseInterface
    {
        $viewFile = $this->redirectView;
        if ($viewFile === null) {
            $viewFile = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'redirect.php';
        } else {
            $viewFile = $this->aliases->get($viewFile);
        }

        $viewData = [
            'url' => $url,
            'enforceRedirect' => $enforceRedirect,
        ];

        $response = $this->responseFactory->createResponse();
        $response->getBody()->write($this->view->renderFile($viewFile, $viewData));

        return $response;
    }

    /**
     * This method is invoked in case of successful authentication via auth client.
     *
     * @param AuthClientInterface $client auth client instance.
     *
     * @throws InvalidConfigException on invalid success callback.
     * @throws Throwable
     * @throws ViewNotFoundException
     *
     * @return ResponseInterface response instance.
     */
    private function authSuccess(AuthClientInterface $client): ResponseInterface
    {
        if (!is_callable($this->successCallback)) {
            throw new InvalidConfigException(
                '"' . self::class . '::$successCallback" should be a valid callback.'
            );
        }

        $response = ($this->successCallback)($client);
        if ($response instanceof ResponseInterface) {
            return $response;
        }

        return $this->redirectSuccess();
    }

    /**
     * Redirect to the URL. If URL is null, {@see successUrl} will be used.
     *
     * @param string|null $url URL to redirect.
     *
     * @throws Throwable
     * @throws ViewNotFoundException
     *
     * @return ResponseInterface response instance.
     */
    private function redirectSuccess(?string $url = null): ResponseInterface
    {
        if ($url === null) {
            $url = $this->successUrl;
        }
        return $this->redirect($url);
    }

    /**
     * Performs OAuth1 auth flow.
     *
     * @param OAuth1 $client auth client instance.
     * @param ServerRequestInterface $request
     *
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws ViewNotFoundException
     * @throws \Yiisoft\Factory\Exception\InvalidConfigException
     *
     * @return ResponseInterface action response.
     */
    private function authOAuth1(OAuth1 $client, ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();

        // user denied error
        if (isset($queryParams['denied']) && $queryParams['denied'] !== null) {
            return $this->authCancel($client);
        }

        if (($oauthToken = $queryParams['oauth_token'] ?? $request->getParsedBody()['oauth_token'] ?? null) !== null) {
            // Upgrade to access token.
            $client->fetchAccessToken($request, $oauthToken);
            return $this->authSuccess($client);
        }

        // Get authorization URL.
        $url = $client->buildAuthUrl($request);
        // Redirect to authorization URL.
        return $this->responseFactory
            ->createResponse(Status::MOVED_PERMANENTLY)
            ->withHeader('Location', $url);
    }

    /**
     * Performs OpenID auth flow.
     *
     * @param OpenId $client auth client instance.
     * @param ServerRequestInterface $request
     *
     * @throws InvalidConfigException
     * @throws Throwable
     * @throws ViewNotFoundException
     *
     * @return ResponseInterface action response.
     */
    private function authOpenId(OpenId $client, ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();
        $bodyParams = $request->getParsedBody();
        $mode = $queryParams['openid_mode'] ?? $bodyParams['openid_mode'] ?? null;

        if (empty($mode)) {
            return $this->responseFactory
                ->createResponse(Status::MOVED_PERMANENTLY)
                ->withHeader('Location', $client->buildAuthUrl($request));
        }

        switch ($mode) {
            case 'id_res':
                if ($client->validate()) {
                    return $this->authSuccess($client);
                }
                $response = $this->responseFactory->createResponse(Status::BAD_REQUEST);
                $response->getBody()->write(
                    'Unable to complete the authentication because the required data was not received.'
                );
                return $response;
            case 'cancel':
                return $this->authCancel($client);
            default:
                return $this->responseFactory->createResponse(Status::BAD_REQUEST);
        }
    }
}
