Feature: LLM Surface invocation
  Operators publish governed LLM access as a Surface so callers can use the provider through Agent Stream controls.

  Scenario: Caller receives a provider chat completion through an LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "alpha-chat" for route "/chat"
    When the caller sends a chat completion request to LLM Surface "alpha-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request

  Scenario: Caller cannot reach a provider through an unpublished LLM Surface route
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And no LLM Surface is configured for route "/missing"
    When the caller sends a chat completion request to route "/missing"
    Then the caller receives a not found response
    And provider "bravo" received no chat completion requests

  Scenario: Published LLM Surface routes call their own providers
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "alpha-chat" for route "/chat" targeting provider "bravo"
    And the operator has published LLM Surface "beta-chat" for route "/backup-chat" targeting provider "charlie"
    When the caller sends a chat completion request to LLM Surface "beta-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received the chat completion request
    And provider "bravo" received no chat completion requests

  Scenario: Caller receives a stable error when the provider is unavailable for chat completions
    Given the operator can use the Admin API
    And provider "bravo" is unavailable for chat completions
    And the operator has published LLM Surface "alpha-chat" for route "/chat"
    When the caller sends a chat completion request to LLM Surface "alpha-chat"
    Then the caller receives a provider error response
    And provider "bravo" received the chat completion request
