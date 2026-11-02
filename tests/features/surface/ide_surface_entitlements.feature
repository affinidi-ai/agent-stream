Feature: IDE Surface entitlements
  IDE callers discover and invoke only models permitted by their member and team access, while temporary quota exhaustion remains visible.

  Scenario: Team membership filters IDE model discovery
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And the operator has published LLM Surface "research-chat" for route "/ide-research-chat" targeting provider "charlie"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And member "Bob" is identified by header "X-Caller-Email" value "bob@example.test"
    And team "Platform" contains member "Alice" without a usage cap
    And team "Research" contains member "Bob" without a usage cap
    And LLM Surface "platform-chat" is available only to team "Platform"
    And LLM Surface "research-chat" is available only to team "Research"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    And IDE Surface "developer-tools" publishes LLM Surface "research-chat" as model "research"
    When member "Alice" discovers models from IDE Surface "developer-tools"
    Then model "platform" is available to the caller
    And model "research" is not available to the caller

  Scenario: Different teams receive different IDE model menus
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And the operator has published LLM Surface "research-chat" for route "/ide-research-chat" targeting provider "charlie"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And member "Bob" is identified by header "X-Caller-Email" value "bob@example.test"
    And team "Platform" contains member "Alice" without a usage cap
    And team "Research" contains member "Bob" without a usage cap
    And LLM Surface "platform-chat" is available only to team "Platform"
    And LLM Surface "research-chat" is available only to team "Research"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    And IDE Surface "developer-tools" publishes LLM Surface "research-chat" as model "research"
    When member "Bob" discovers models from IDE Surface "developer-tools"
    Then model "platform" is not available to the caller
    And model "research" is available to the caller

  Scenario: Unrecognized caller cannot discover team-restricted models
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And team "Platform" contains member "Alice" without a usage cap
    And LLM Surface "platform-chat" is available only to team "Platform"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    When the caller discovers models from IDE Surface "developer-tools"
    Then model "platform" is not available to the caller

  Scenario: Hidden team-restricted model cannot be dispatched directly
    Given provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "research-chat" for route "/ide-research-chat" targeting provider "charlie"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And member "Bob" is identified by header "X-Caller-Email" value "bob@example.test"
    And team "Platform" contains member "Alice" without a usage cap
    And team "Research" contains member "Bob" without a usage cap
    And LLM Surface "research-chat" is available only to team "Research"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "research-chat" as model "research"
    When member "Alice" invokes model "research" through IDE Surface "developer-tools"
    Then member "Alice" is rejected because the model requires a different team
    And provider "charlie" received no chat completion requests

  Scenario: Entitled member dispatches an IDE model
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And team "Platform" contains member "Alice" without a usage cap
    And LLM Surface "platform-chat" is available only to team "Platform"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    When member "Alice" invokes model "platform" through IDE Surface "developer-tools"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received 1 chat completion request

  Scenario: IDE source authentication blocks unauthenticated discovery
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    And secret "ide-api-keys" contains caller API key "valid-ide-key"
    And IDE Surface "developer-tools" requires "API Key" source authentication using secret "ide-api-keys"
    When the caller discovers models from IDE Surface "developer-tools"
    Then the caller is rejected by source authentication

  Scenario: Authenticated caller discovers IDE models
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    And secret "ide-api-keys" contains caller API key "valid-ide-key"
    And IDE Surface "developer-tools" requires "API Key" source authentication using secret "ide-api-keys"
    When the caller discovers models from IDE Surface "developer-tools" with caller API key "valid-ide-key"
    Then model "platform" is available to the caller

  Scenario: IDE source authentication prevents direct model dispatch bypass
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    And secret "ide-api-keys" contains caller API key "valid-ide-key"
    And IDE Surface "developer-tools" requires "API Key" source authentication using secret "ide-api-keys"
    When the caller invokes model "platform" through IDE Surface "developer-tools"
    Then the caller is rejected by source authentication
    And provider "bravo" received no chat completion requests

  Scenario: IDE Surface policy blocks discovery
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    And IDE Surface "developer-tools" policy allows caller access tier "standard"
    When the caller discovers models from IDE Surface "developer-tools" with access tier "restricted"
    Then the caller is rejected by IDE Surface policy

  Scenario: LLM Surface policy hides an IDE model from discovery
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And LLM Surface "platform-chat" policy allows caller access tier "standard"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    When the caller discovers models from IDE Surface "developer-tools" with access tier "restricted"
    Then model "platform" is not available to the caller

  Scenario: Hidden policy-restricted model cannot be dispatched directly
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And LLM Surface "platform-chat" policy allows caller access tier "standard"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    When the caller invokes model "platform" through IDE Surface "developer-tools" with access tier "restricted"
    Then the caller is rejected by LLM Surface policy
    And provider "bravo" received no chat completion requests

  Scenario: Quota exhaustion does not remove an entitled IDE model
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And team "Platform" contains member "Alice" with a monthly token cap of 10
    And LLM Surface "platform-chat" is available only to team "Platform"
    And member "Alice" has consumed 10 tokens through LLM Surface "platform-chat"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    When member "Alice" discovers models from IDE Surface "developer-tools"
    Then model "platform" is available to the caller

  Scenario: Quota exhaustion blocks IDE model dispatch without invoking the provider
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "platform-chat" for route "/ide-platform-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And team "Platform" contains member "Alice" with a monthly token cap of 10
    And LLM Surface "platform-chat" is available only to team "Platform"
    And member "Alice" has consumed 10 tokens through LLM Surface "platform-chat"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "platform-chat" as model "platform"
    When member "Alice" invokes model "platform" through IDE Surface "developer-tools"
    Then member "Alice" is rejected because team "Platform" token cap is exhausted
    And provider "bravo" received 1 chat completion request
