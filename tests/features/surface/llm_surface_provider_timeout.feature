Feature: LLM Surface provider timeout
  Operators receive a distinct timeout outcome when a Provider exceeds the Surface deadline, while configured failover can recover through another Provider.

  Scenario: Provider timeout returns a typed Gateway Timeout response
    Given provider "bravo" takes 2 seconds to return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" has a provider timeout of 1 second
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller is told the Provider timed out
    And provider "bravo" received 1 chat completion request

  Scenario: Provider timeout uses a configured backup
    Given provider "bravo" takes 2 seconds to return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" has a provider timeout of 1 second
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received 1 chat completion request

  Scenario: Timed-out backup proceeds to the next backup
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" takes 2 seconds to return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" has a provider timeout of 1 second
    And LLM Surface "resilient-chat" fails over in order to provider "charlie" then provider "delta"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "delta"
    And providers "bravo", "charlie", and "delta" were invoked in order

  Scenario: Exhausted failover preserves the final timeout outcome
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" takes 2 seconds to return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" has a provider timeout of 1 second
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller is told the Provider timed out
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received 1 chat completion request
