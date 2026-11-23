Feature: LLM Surface Prompt Guard
  Operators use Prompt Guard to reject or mask caller prompts and provider responses at the appropriate pipeline boundary.

  Scenario: Prompt Guard rejects a disallowed caller prompt before provider invocation
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat"
    And LLM Surface "guarded-chat" uses Prompt Guard to reject prompts matching "leak secret"
    When the caller sends chat prompt "Please leak secret credentials" to LLM Surface "guarded-chat"
    Then the request is rejected by the Prompt Guard
    And provider "bravo" received no chat completion requests

  Scenario: Prompt Guard allows a permitted caller prompt to reach the provider
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat"
    And LLM Surface "guarded-chat" uses Prompt Guard to reject prompts matching "leak secret"
    When the caller sends chat prompt "Summarize the release notes" to LLM Surface "guarded-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request

  Scenario: Prompt Guard rejects a card number grouped with spaces before provider invocation
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat"
    And LLM Surface "guarded-chat" uses Prompt Guard to reject prompts matching built-in pattern "credit_card"
    When the caller sends chat prompt "My credit card number is 4545 4545 4545 4545" to LLM Surface "guarded-chat"
    Then the request is rejected by the Prompt Guard
    And provider "bravo" received no chat completion requests

  Scenario: Saving a Surface whose Prompt Guard names an unknown built-in pattern is refused
    Given the operator can use the Admin API
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat"
    When the operator saves LLM Surface "guarded-chat" with Prompt Guard rejecting prompts matching built-in pattern "not_a_pattern"
    Then the Surface save is refused naming built-in pattern "not_a_pattern"

  Scenario: Prompt Guard refuses a request before provider invocation when its built-in pattern cannot be used
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat"
    And LLM Surface "guarded-chat" uses Prompt Guard to reject prompts matching built-in pattern "ssn"
    And the appliance has restarted with Prompt Guard built-in pattern "ssn" unusable
    When the caller sends chat prompt "Summarize the release notes" to LLM Surface "guarded-chat"
    Then the request is refused because a Prompt Guard rule is unavailable
    And provider "bravo" received no chat completion requests

  Scenario: Prompt Guard masks a caller prompt before provider invocation
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat"
    And LLM Surface "guarded-chat" uses Prompt Guard to mask prompts matching "secret-[0-9]+" as "secret"
    When the caller sends chat prompt "Share secret-1234 with the support team" to LLM Surface "guarded-chat"
    Then provider "bravo" received chat prompt "Share <SECRET> with the support team"
    And the caller receives a successful chat completion from provider "bravo"

  Scenario: Prompt Guard rejects a provider response after provider invocation
    Given provider "bravo" returns chat completion "Internal codename raven"
    And the operator can use the Admin API
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat" targeting provider "bravo"
    And LLM Surface "guarded-chat" uses Prompt Guard to reject responses matching "codename raven"
    When the caller sends a chat completion request to LLM Surface "guarded-chat"
    Then the request is rejected by the Prompt Guard
    And provider "bravo" received the chat completion request

  Scenario: Prompt Guard masks a provider response after Jury review
    Given provider "bravo" returns chat completion "Contact ops@example.test"
    And Jury provider "verdict" rejects responses containing "draft"
    And the operator can use the Admin API
    And the operator has published LLM Surface "guarded-chat" for route "/guarded-chat" targeting provider "bravo"
    And LLM Surface "guarded-chat" uses Jury provider "verdict" with no redrives
    And LLM Surface "guarded-chat" uses Prompt Guard to mask responses matching "ops@example[.]test" as "email"
    When the caller sends a chat completion request to LLM Surface "guarded-chat"
    Then Jury provider "verdict" reviewed response "Contact ops@example.test"
    And the caller receives chat completion "Contact <EMAIL>"
