<?php

declare(strict_types=1);

namespace Yiisoft\Yii\AuthClient;

use Psr\Http\Client\ClientInterface as PsrClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Yii\AuthClient\Exception\InvalidConfigException;
use Yiisoft\Yii\AuthClient\StateStorage\StateStorageInterface;

use function is_array;
use function is_callable;

/**
 * AuthClient is a base Auth Client class.
 *
 * @see AuthClientInterface
 */
abstract class AuthClient implements AuthClientInterface
{
    /**
     * @var array authenticated user attributes.
     */
    protected array $userAttributes = [];
    /**
     * @var array map used to normalize user attributes fetched from external auth service
     * in format: normalizedAttributeName => sourceSpecification
     * 'sourceSpecification' can be:
     * - string, raw attribute name
     * - array, pass to raw attribute value
     * - callable, PHP callback, which should accept array of raw attributes and return normalized value.
     *
     * For example:
     *
     * ```php
     * 'normalizeUserAttributeMap' => [
     *      'about' => 'bio',
     *      'language' => ['languages', 0, 'name'],
     *      'fullName' => function ($attributes) {
     *          return $attributes['firstName'] . ' ' . $attributes['lastName'];
     *      },
     *  ],
     * ```
     */
    protected array $normalizeUserAttributeMap = [];
    /**
     * @var array|null view options in format: optionName => optionValue
     */
    protected ?array $viewOptions = null;

    protected PsrClientInterface $httpClient;

    protected RequestFactoryInterface $requestFactory;

    /**
     * @var StateStorageInterface state storage to be used.
     */
    private StateStorageInterface $stateStorage;

    public function __construct(
        PsrClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StateStorageInterface $stateStorage
    ) {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->stateStorage = $stateStorage;
    }

    /**
     * @throws InvalidConfigException
     *
     * @return array list of user attributes
     */
    public function getUserAttributes(): array
    {
        if ($this->userAttributes === null) {
            $this->userAttributes = $this->normalizeUserAttributes($this->initUserAttributes());
        }

        return $this->userAttributes;
    }

    /**
     * @param array $userAttributes list of user attributes
     *
     * @throws InvalidConfigException
     */
    public function setUserAttributes(array $userAttributes): void
    {
        $this->userAttributes = $this->normalizeUserAttributes($userAttributes);
    }

    /**
     * Normalize given user attributes according to {@see normalizeUserAttributeMap}.
     *
     * @param array $attributes raw attributes.
     *
     * @throws InvalidConfigException on incorrect normalize attribute map.
     *
     * @return array normalized attributes.
     */
    protected function normalizeUserAttributes(array $attributes): array
    {
        foreach ($this->getNormalizeUserAttributeMap() as $normalizedName => $actualName) {
            if (is_scalar($actualName)) {
                if (array_key_exists($actualName, $attributes)) {
                    $attributes[$normalizedName] = $attributes[$actualName];
                }
            } elseif (is_callable($actualName)) {
                $attributes[$normalizedName] = $actualName($attributes);
            } elseif (is_array($actualName)) {
                $haystack = $attributes;
                $searchKeys = $actualName;
                $isFound = true;
                while (($key = array_shift($searchKeys)) !== null) {
                    if (is_array($haystack) && array_key_exists($key, $haystack)) {
                        $haystack = $haystack[$key];
                    } else {
                        $isFound = false;
                        break;
                    }
                }
                if ($isFound) {
                    $attributes[$normalizedName] = $haystack;
                }
            } else {
                throw new InvalidConfigException(
                    'Invalid actual name "' . gettype($actualName) . '" specified at "' . static::class

                    . '::normalizeUserAttributeMap"'
                );
            }
        }

        return $attributes;
    }

    /**
     * @return array normalize user attribute map.
     */
    public function getNormalizeUserAttributeMap(): array
    {
        if ($this->normalizeUserAttributeMap === null) {
            $this->normalizeUserAttributeMap = $this->defaultNormalizeUserAttributeMap();
        }

        return $this->normalizeUserAttributeMap;
    }

    /**
     * @param array $normalizeUserAttributeMap normalize user attribute map.
     */
    public function setNormalizeUserAttributeMap(array $normalizeUserAttributeMap): void
    {
        $this->normalizeUserAttributeMap = $normalizeUserAttributeMap;
    }

    /**
     * Returns the default {@see normalizeUserAttributeMap} value.
     * Particular client may override this method in order to provide specific default map.
     *
     * @return array normalize attribute map.
     */
    protected function defaultNormalizeUserAttributeMap(): array
    {
        return [];
    }

    /**
     * Initializes authenticated user attributes.
     *
     * @return array auth user attributes.
     */
    abstract protected function initUserAttributes(): array;

    /**
     * @return array view options in format: optionName => optionValue
     */
    public function getViewOptions(): array
    {
        if ($this->viewOptions === null) {
            $this->viewOptions = $this->defaultViewOptions();
        }

        return $this->viewOptions;
    }

    /**
     * @param array $viewOptions view options in format: optionName => optionValue
     */
    public function setViewOptions(array $viewOptions): void
    {
        $this->viewOptions = $viewOptions;
    }

    /**
     * Returns the default {@see viewOptions} value.
     * Particular client may override this method in order to provide specific default view options.
     *
     * @return array list of default {@see viewOptions}
     */
    protected function defaultViewOptions(): array
    {
        return [];
    }

    abstract public function buildAuthUrl(ServerRequestInterface $incomingRequest, array $params): string;

    public function createRequest(string $method, string $uri): RequestInterface
    {
        return $this->requestFactory->createRequest($method, $uri);
    }

    /**
     * Sets persistent state.
     *
     * @param string $key state key.
     * @param mixed $value state value
     *
     * @return $this the object itself
     */
    protected function setState(string $key, $value): self
    {
        $this->stateStorage->set($this->getStateKeyPrefix() . $key, $value);
        return $this;
    }

    /**
     * Returns session key prefix, which is used to store internal states.
     *
     * @return string session key prefix.
     */
    protected function getStateKeyPrefix(): string
    {
        return static::class . '_' . $this->getName() . '_';
    }

    /**
     * Returns persistent state value.
     *
     * @param string $key state key.
     *
     * @return mixed state value.
     */
    protected function getState(string $key)
    {
        return $this->stateStorage->get($this->getStateKeyPrefix() . $key);
    }

    /**
     * Removes persistent state value.
     *
     * @param string $key state key.
     */
    protected function removeState(string $key): void
    {
        $this->stateStorage->remove($this->getStateKeyPrefix() . $key);
    }

    protected function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->httpClient->sendRequest($request);
    }
}
