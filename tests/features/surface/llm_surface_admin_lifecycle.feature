Feature: LLM Surface admin lifecycle
  Operators manage published LLM Surfaces without restarting Agent Stream or disrupting unrelated routes.

  Scenario: Operator publishes an LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And no LLM Surface is configured for route "/lifecycle-chat"
    When the operator publishes LLM Surface "lifecycle-chat" for route "/lifecycle-chat" targeting provider "bravo"
    Then publication is persisted for LLM Surface "lifecycle-chat" at route "/lifecycle-chat" using provider "bravo"

  Scenario: Operator changes the provider used by a published LLM Surface
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "lifecycle-chat" for route "/lifecycle-chat" targeting provider "bravo"
    When the operator changes LLM Surface "lifecycle-chat" to use provider "charlie"
    Then the provider change is persisted for LLM Surface "lifecycle-chat" using provider "charlie"

  Scenario: Updated LLM Surface calls the new provider
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has changed LLM Surface "lifecycle-chat" for route "/lifecycle-chat" from provider "bravo" to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "lifecycle-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received the chat completion request
    And provider "bravo" received no chat completion requests

  Scenario: Disabled LLM Surface route is unavailable to callers
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has disabled LLM Surface "lifecycle-chat" for route "/lifecycle-chat"
    When the caller sends a chat completion request to route "/lifecycle-chat"
    Then the caller receives a not found response
    And provider "bravo" received no chat completion requests

  Scenario: Disabling one LLM Surface does not affect another published route
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "lifecycle-chat" for route "/lifecycle-chat" targeting provider "bravo"
    And the operator has published LLM Surface "backup-lifecycle-chat" for route "/backup-lifecycle-chat" targeting provider "charlie"
    And the operator has disabled LLM Surface "lifecycle-chat"
    When the caller sends a chat completion request to LLM Surface "backup-lifecycle-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received the chat completion request
    And provider "bravo" received no chat completion requests

  Scenario: Invalid route update preserves the published LLM Surface
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "lifecycle-chat" for route "/lifecycle-chat" targeting provider "bravo"
    And the operator has published LLM Surface "backup-lifecycle-chat" for route "/backup-lifecycle-chat" targeting provider "charlie"
    When the operator changes LLM Surface "lifecycle-chat" to route "/backup-lifecycle-chat"
    Then the LLM Surface update is rejected because the route is already published
    And LLM Surface "lifecycle-chat" retains route "/lifecycle-chat" and provider "bravo"
