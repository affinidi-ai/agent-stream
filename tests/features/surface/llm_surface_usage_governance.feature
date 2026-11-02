Feature: LLM Surface usage governance
  Operators protect providers and control shared consumption with Surface, member, and team limits.

  Scenario: Surface request limit rejects calls above the configured rate
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" allows 1 request per minute
    And the caller has used the available request for LLM Surface "governed-chat"
    When the caller sends a chat completion request to LLM Surface "governed-chat"
    Then the caller is rejected by the Surface request limit
    And provider "bravo" received 1 chat completion request

  Scenario: Surface request limit does not invoke a failover provider
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" allows 1 request per minute
    And LLM Surface "governed-chat" fails over to provider "charlie"
    And the caller has used the available request for LLM Surface "governed-chat"
    When the caller sends a chat completion request to LLM Surface "governed-chat"
    Then the caller is rejected by the Surface request limit
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received no chat completion requests

  Scenario: Surface monthly token cap rejects further provider calls
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" has a monthly token cap of 10
    And the caller has consumed 10 tokens through LLM Surface "governed-chat"
    When the caller sends a chat completion request to LLM Surface "governed-chat"
    Then the caller is rejected because the Surface token cap is exhausted
    And provider "bravo" received 1 chat completion request

  Scenario: Surface monthly token cap still applies after the appliance restarts
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" has a monthly token cap of 10
    And the caller has consumed 10 tokens through LLM Surface "governed-chat"
    And the appliance has restarted
    When the caller sends a chat completion request to LLM Surface "governed-chat"
    Then the caller is rejected because the Surface token cap is exhausted
    And provider "bravo" received 1 chat completion request

  Scenario: A promoted Standby appliance enforces the Surface token cap reached on the Active appliance
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" has a monthly token cap of 10
    And a Standby appliance shares storage with the Active appliance
    And the caller has consumed 10 tokens through LLM Surface "governed-chat"
    And the Standby appliance has been promoted to replace the Active appliance
    When the caller sends a chat completion request to LLM Surface "governed-chat"
    Then the caller is rejected because the Surface token cap is exhausted
    And provider "bravo" received 1 chat completion request

  Scenario: A promoted Standby appliance enforces the member token cap reached on the Active appliance
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And the operator has published LLM Surface "governed-chat-two" for route "/governed-chat-two" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly token cap of 10
    And both governed LLM Surfaces enforce member and team usage
    And a Standby appliance shares storage with the Active appliance
    And member "Alice" has consumed 10 tokens through LLM Surface "governed-chat"
    And the Standby appliance has been promoted to replace the Active appliance
    When member "Alice" invokes LLM Surface "governed-chat-two"
    Then member "Alice" is rejected because the member token cap is exhausted
    And provider "bravo" received 1 chat completion request

  Scenario: Surface token cap does not invoke a failover provider
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" has a monthly token cap of 10
    And LLM Surface "governed-chat" fails over to provider "charlie"
    And the caller has consumed 10 tokens through LLM Surface "governed-chat"
    When the caller sends a chat completion request to LLM Surface "governed-chat"
    Then the caller is rejected because the Surface token cap is exhausted
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received no chat completion requests

  Scenario: Member request limit applies across LLM Surfaces
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And the operator has published LLM Surface "governed-chat-two" for route "/governed-chat-two" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a limit of 1 request per minute
    And both governed LLM Surfaces enforce member and team usage
    And member "Alice" has invoked LLM Surface "governed-chat"
    When member "Alice" invokes LLM Surface "governed-chat-two"
    Then member "Alice" is rejected by the member request limit
    And provider "bravo" received 1 chat completion request

  Scenario: Member monthly token cap applies across LLM Surfaces
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And the operator has published LLM Surface "governed-chat-two" for route "/governed-chat-two" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly token cap of 10
    And both governed LLM Surfaces enforce member and team usage
    And member "Alice" has consumed 10 tokens through LLM Surface "governed-chat"
    When member "Alice" invokes LLM Surface "governed-chat-two"
    Then member "Alice" is rejected because the member token cap is exhausted
    And provider "bravo" received 1 chat completion request

  Scenario: Team monthly token cap aggregates usage across members
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And member "Bob" is identified by header "X-Caller-Email" value "bob@example.test"
    And team "Platform" contains members "Alice" and "Bob" with a monthly token cap of 10
    And LLM Surface "governed-chat" enforces member and team usage
    And member "Alice" has consumed 10 tokens through LLM Surface "governed-chat"
    When member "Bob" invokes LLM Surface "governed-chat"
    Then member "Bob" is rejected because team "Platform" token cap is exhausted
    And provider "bravo" received 1 chat completion request

  Scenario: A spent member budget refuses calls on the operator's provider key
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" prices input and output tokens at 1 dollar per 1000 tokens
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly budget of 0.005 dollars
    And LLM Surface "governed-chat" enforces member and team usage
    And member "Alice" has invoked LLM Surface "governed-chat"
    When member "Alice" invokes LLM Surface "governed-chat"
    Then member "Alice" is rejected because the member budget is spent
    And provider "bravo" received 1 chat completion request

  Scenario: A spent member budget still serves calls on the caller's own provider key
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" prices input and output tokens at 1 dollar per 1000 tokens
    And LLM Surface "governed-chat" sends the operator's provider key from secret "operator-provider-key"
    And LLM Surface "governed-chat" accepts the caller's own provider key
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly budget of 0.005 dollars
    And LLM Surface "governed-chat" enforces member and team usage
    And member "Alice" has invoked LLM Surface "governed-chat"
    When member "Alice" invokes LLM Surface "governed-chat" with their own provider key
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received 2 chat completion requests
    And provider "bravo" received the caller's own provider key only on the last request

  Scenario: A batch on the operator's provider key is refused even with credit left
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" prices input and output tokens at 1 dollar per 1000 tokens
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly budget of 100.0 dollars
    And LLM Surface "governed-chat" enforces member and team usage
    When member "Alice" creates a batch through LLM Surface "governed-chat"
    Then member "Alice" is refused because a batch on the operator's provider key is not metered

  Scenario: A stream on the operator's provider key that reports no usage still spends the member budget
    Given provider "bravo" can stream chat completion "Hello from bravo" without reporting usage
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" declares a price of 1 dollar per 1000 tokens
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly budget of 0.005 dollars
    And LLM Surface "governed-chat" enforces member and team usage
    And member "Alice" has streamed a chat completion from LLM Surface "governed-chat"
    When member "Alice" invokes LLM Surface "governed-chat"
    Then member "Alice" is rejected because the member budget is spent

  Scenario: A hosted tool on the operator's provider key is refused even with credit left
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" prices input and output tokens at 1 dollar per 1000 tokens
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly budget of 100.0 dollars
    And LLM Surface "governed-chat" enforces member and team usage
    When member "Alice" asks LLM Surface "governed-chat" to search the web
    Then member "Alice" is refused because a hosted tool on the operator's provider key is not metered
    And provider "bravo" received no chat completion requests
