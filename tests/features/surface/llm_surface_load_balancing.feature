Feature: LLM Surface load balancing
  Operators distribute requests across provider pools while upstream failures fall through and content-safety decisions remain final.

  Scenario: Zero primary weight drains first-pick traffic to a pool target
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "balanced-chat" for route "/balanced-chat" targeting provider "bravo"
    And LLM Surface "balanced-chat" balances traffic with primary weight 0 and provider "charlie" weight 1
    When the caller sends a chat completion request to LLM Surface "balanced-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "bravo" received no chat completion requests
    And provider "charlie" received 1 chat completion request

  Scenario: Equal weights select pool members in deterministic rotation
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "balanced-chat" for route "/balanced-chat" targeting provider "bravo"
    And LLM Surface "balanced-chat" balances traffic with primary weight 1 and provider "charlie" weight 1
    And the caller has received one chat completion from provider "bravo" through LLM Surface "balanced-chat"
    When the caller sends a chat completion request to LLM Surface "balanced-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received 1 chat completion request

  Scenario: Failed primary selection falls through to a pool target
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "balanced-chat" for route "/balanced-chat" targeting provider "bravo"
    And LLM Surface "balanced-chat" balances traffic with primary weight 1 and provider "charlie" weight 1
    When the caller sends a chat completion request to LLM Surface "balanced-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And providers "bravo" then "charlie" were invoked in order

  Scenario: Failed target selection falls through to the primary provider
    Given provider "bravo" can return chat completions
    And provider "charlie" is unavailable for chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "balanced-chat" for route "/balanced-chat" targeting provider "bravo"
    And LLM Surface "balanced-chat" balances traffic with primary weight 0 and provider "charlie" weight 1
    When the caller sends a chat completion request to LLM Surface "balanced-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And providers "charlie" then "bravo" were invoked in order

  Scenario: Prompt Guard rejection does not invoke the provider pool
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "balanced-chat" for route "/balanced-chat" targeting provider "bravo"
    And LLM Surface "balanced-chat" balances traffic with primary weight 1 and provider "charlie" weight 1
    And LLM Surface "balanced-chat" uses Prompt Guard to reject prompts matching "blocked"
    When the caller sends chat prompt "This request is blocked" to LLM Surface "balanced-chat"
    Then the request is rejected by the Prompt Guard
    And provider "bravo" received no chat completion requests
    And provider "charlie" received no chat completion requests

  Scenario: Jury rejection does not fall through to another pool member
    Given provider "bravo" returns chat completion "Unsafe answer"
    And provider "charlie" can return chat completions
    And Jury provider "verdict" rejects responses containing "Unsafe answer"
    And the operator can use the Admin API
    And the operator has published LLM Surface "balanced-chat" for route "/balanced-chat" targeting provider "bravo"
    And LLM Surface "balanced-chat" balances traffic with primary weight 1 and provider "charlie" weight 1
    And LLM Surface "balanced-chat" uses Jury provider "verdict" with no redrives
    When the caller sends a chat completion request to LLM Surface "balanced-chat"
    Then the request is rejected by the Jury
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received no chat completion requests

  Scenario: Load balancing takes precedence over failover configuration
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "balanced-chat" for route "/balanced-chat" targeting provider "bravo"
    And LLM Surface "balanced-chat" fails over to provider "delta"
    And LLM Surface "balanced-chat" balances traffic with primary weight 0 and provider "charlie" weight 1
    When the caller sends a chat completion request to LLM Surface "balanced-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "bravo" received no chat completion requests
    And provider "charlie" received 1 chat completion request
    And provider "delta" received no chat completion requests
