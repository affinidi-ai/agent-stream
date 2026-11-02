Feature: LLM Surface provider failover
  Operators configure ordered backup providers so eligible upstream failures recover without bypassing content-safety decisions.

  Scenario: Successful primary provider does not invoke backups
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request
    And provider "charlie" received no chat completion requests

  Scenario: Primary provider failure uses the first backup
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "bravo" received the chat completion request
    And provider "charlie" received the chat completion request
    And the failover metrics record a successful failover to the first backup

  Scenario: Failover tries backup providers in order until one succeeds
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" is unavailable for chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" fails over in order to provider "charlie" then provider "delta"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "delta"
    And providers "bravo", "charlie", and "delta" were invoked in order

  Scenario: Exhausted failover returns the final provider error
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" is unavailable for chat completions
    And provider "delta" is unavailable for chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" fails over in order to provider "charlie" then provider "delta"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller is told all failover providers are unavailable
    And provider "bravo" received the chat completion request
    And provider "charlie" received the chat completion request
    And provider "delta" received the chat completion request
    And the failover metrics record all backups exhausted

  Scenario: Prompt Guard rejection does not invoke failover providers
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" uses Prompt Guard to reject prompts matching "blocked"
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    When the caller sends chat prompt "This request is blocked" to LLM Surface "resilient-chat"
    Then the request is rejected by the Prompt Guard
    And provider "bravo" received no chat completion requests
    And provider "charlie" received no chat completion requests

  Scenario: Jury rejection does not invoke a backup provider
    Given provider "bravo" returns chat completion "Unsafe answer"
    And provider "charlie" can return chat completions
    And Jury provider "verdict" rejects responses containing "Unsafe answer"
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" uses Jury provider "verdict" with no redrives
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the request is rejected by the Jury
    And provider "bravo" received the chat completion request
    And provider "charlie" received no chat completion requests

  Scenario: Primary provider authentication failure uses the first backup
    Given provider "bravo" is unauthorized for chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "bravo" received the chat completion request
    And provider "charlie" received the chat completion request

  Scenario: An open primary circuit fails over without re-invoking the primary
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" opens its circuit breaker after 1 provider failure
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    And the caller has already sent a chat completion request to LLM Surface "resilient-chat"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received 2 chat completion requests

  Scenario: Content denials do not open the provider circuit breaker
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "resilient-chat" for route "/resilient-chat" targeting provider "bravo"
    And LLM Surface "resilient-chat" uses Prompt Guard to reject prompts matching "blocked"
    And LLM Surface "resilient-chat" opens its circuit breaker after 1 provider failure
    And LLM Surface "resilient-chat" fails over to provider "charlie"
    And the caller has already had prompt "This request is blocked" rejected by LLM Surface "resilient-chat"
    When the caller sends a chat completion request to LLM Surface "resilient-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "charlie" received no chat completion requests
