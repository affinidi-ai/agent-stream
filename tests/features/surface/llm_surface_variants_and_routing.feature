Feature: LLM Surface variants and routing
  Operators steer callers to alternate Surface configurations through explicit variants, routing rules, and controlled canary splits.

  Scenario: Caller explicitly selects a provider variant
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" has variant "premium" targeting provider "charlie"
    When the caller sends a chat completion request to variant "premium" of LLM Surface "variant-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received the chat completion request
    And provider "bravo" received no chat completion requests

  Scenario: Header routing rule selects a variant
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" has variant "premium" targeting provider "charlie"
    And LLM Surface "variant-chat" routes header "X-Tier" value "premium" to variant "premium"
    When the caller sends a chat completion request with header "X-Tier" value "premium" to LLM Surface "variant-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received the chat completion request
    And provider "bravo" received no chat completion requests

  Scenario: Body-field routing rule selects an inline provider
    Given provider "bravo" can return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" routes body field "workload" value "batch" to provider "delta"
    When the caller sends a chat completion request with body field "workload" value "batch" to LLM Surface "variant-chat"
    Then the caller receives a successful chat completion from provider "delta"
    And provider "delta" received the chat completion request
    And provider "bravo" received no chat completion requests

  Scenario: Modality routing rule sends an image request to a vision variant
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" has vision variant "vision" targeting provider "charlie"
    And LLM Surface "variant-chat" routes modality "image" to variant "vision"
    When the caller sends a chat completion request with an image to LLM Surface "variant-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received a chat completion request with an image
    And provider "bravo" received no chat completion requests

  Scenario: Canary sends all eligible traffic to a variant
    Given provider "bravo" can return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" has variant "next" targeting provider "delta"
    And LLM Surface "variant-chat" sends 100 percent of eligible traffic to variant "next"
    When the caller sends a chat completion request to LLM Surface "variant-chat"
    Then the caller receives a successful chat completion from provider "delta"
    And provider "delta" received the chat completion request
    And provider "bravo" received no chat completion requests

  Scenario: A canary to another provider never receives the caller's own provider key
    Given provider "bravo" can return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" accepts the caller's own provider key
    And LLM Surface "variant-chat" has variant "next" targeting provider "delta"
    And LLM Surface "variant-chat" sends 100 percent of eligible traffic to variant "next"
    When the caller sends a chat completion request to LLM Surface "variant-chat" with their own provider key
    Then the caller receives a successful chat completion from provider "delta"
    And provider "delta" did not receive header "Authorization"
    And provider "bravo" received no chat completion requests

  Scenario: An inline routing target never receives the caller's own provider key
    Given provider "bravo" can return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" accepts the caller's own provider key
    And LLM Surface "variant-chat" routes body field "workload" value "batch" to provider "delta"
    When the caller sends a chat completion request with body field "workload" value "batch" to LLM Surface "variant-chat" with their own provider key
    Then the caller receives a successful chat completion from provider "delta"
    And provider "delta" did not receive header "Authorization"
    And provider "bravo" received no chat completion requests

  Scenario: Explicit variant takes precedence over routing rules and canary
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" has variant "premium" targeting provider "charlie"
    And LLM Surface "variant-chat" has variant "next" targeting provider "delta"
    And LLM Surface "variant-chat" routes header "X-Tier" value "next" to variant "next"
    And LLM Surface "variant-chat" sends 100 percent of eligible traffic to variant "next"
    When the caller sends a chat completion request with header "X-Tier" value "next" to variant "premium" of LLM Surface "variant-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received the chat completion request
    And provider "delta" received no chat completion requests
    And provider "bravo" received no chat completion requests

  Scenario: Routing rule takes precedence over canary
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And provider "delta" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" has variant "premium" targeting provider "charlie"
    And LLM Surface "variant-chat" has variant "next" targeting provider "delta"
    And LLM Surface "variant-chat" routes header "X-Tier" value "premium" to variant "premium"
    And LLM Surface "variant-chat" sends 100 percent of eligible traffic to variant "next"
    When the caller sends a chat completion request with header "X-Tier" value "premium" to LLM Surface "variant-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And provider "charlie" received the chat completion request
    And provider "delta" received no chat completion requests
    And provider "bravo" received no chat completion requests

  Scenario: Disabled variant rejects explicitly addressed traffic
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "variant-chat" for route "/variant-chat" targeting provider "bravo"
    And LLM Surface "variant-chat" has disabled variant "premium" targeting provider "charlie"
    When the caller sends a chat completion request to variant "premium" of LLM Surface "variant-chat"
    Then the caller is told variant "premium" is disabled
    And provider "charlie" received no chat completion requests
    And provider "bravo" received no chat completion requests
