Feature: Source authentication for LLM Surfaces
  Operators require caller credentials at a Surface route so only authorized callers can reach the provider.

  Scenario: Caller without required API key cannot invoke an LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When the caller sends a chat completion request to LLM Surface "keyed-chat" without caller credentials
    Then the caller is rejected by source authentication
    And provider "bravo" received no chat completion requests

  Scenario: Caller with required API key can invoke an LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When the caller sends a chat completion request to LLM Surface "keyed-chat" with caller API key "valid-caller-key"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request
    And provider "bravo" did not receive header "X-API-Key"

  Scenario: Caller with a valid JWT can invoke without exposing the bearer token to the provider
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "jwt-chat" for route "/jwt-chat"
    And LLM Surface "jwt-chat" requires JWT source authentication for issuer "https://issuer.example.test" and audience "agent-stream"
    When the caller sends a chat completion request to LLM Surface "jwt-chat" with a valid JWT
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request
    And provider "bravo" did not receive header "Authorization"

  Scenario: A caller's JWT is never sent to the provider as their own provider key
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "jwt-chat" for route "/jwt-chat"
    And LLM Surface "jwt-chat" requires JWT source authentication for issuer "https://issuer.example.test" and audience "agent-stream"
    And LLM Surface "jwt-chat" accepts the caller's own provider key
    When the caller sends a chat completion request to LLM Surface "jwt-chat" with a valid JWT
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" did not receive header "Authorization"

  Scenario: A caller behind a JWT sends their own provider key in its own header
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "jwt-chat" for route "/jwt-chat"
    And LLM Surface "jwt-chat" requires JWT source authentication for issuer "https://issuer.example.test" and audience "agent-stream"
    And LLM Surface "jwt-chat" accepts the caller's own provider key
    When the caller sends a chat completion request to LLM Surface "jwt-chat" with a valid JWT and their own provider key
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the caller's own provider key only on the last request

  Scenario: A caller's own provider key in Authorization is preferred to a provider identity token
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "ordinary-chat" for route "/ordinary-chat"
    And LLM Surface "ordinary-chat" accepts the caller's own provider key
    When the caller sends a chat completion request to LLM Surface "ordinary-chat" with their own provider key and a provider identity token
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the caller's own provider key only on the last request

  Scenario: A caller API key repeated as a bearer token is never sent to the provider
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    And LLM Surface "keyed-chat" accepts the caller's own provider key
    When the caller sends a chat completion request to LLM Surface "keyed-chat" with caller API key "valid-caller-key" repeated as its bearer token
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" did not receive header "Authorization"

  Scenario: Caller with an invalid JWT cannot invoke an LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "jwt-chat" for route "/jwt-chat"
    And LLM Surface "jwt-chat" requires JWT source authentication for issuer "https://issuer.example.test" and audience "agent-stream"
    When the caller sends a chat completion request to LLM Surface "jwt-chat" with an invalid JWT
    Then the caller is rejected by source authentication
    And provider "bravo" received no chat completion requests

  Scenario: Caller with the wrong API key cannot invoke an LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When the caller sends a chat completion request to LLM Surface "keyed-chat" with caller API key "wrong-caller-key"
    Then the caller is rejected by source authentication
    And provider "bravo" received no chat completion requests

  Scenario: Prompt Guard still rejects a disallowed prompt from an authenticated caller
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-guarded-chat" for route "/keyed-guarded-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-guarded-chat" requires "API Key" source authentication using secret "caller-api-keys"
    And LLM Surface "keyed-guarded-chat" uses Prompt Guard to reject prompts matching "leak secret"
    When the caller sends chat prompt "Please leak secret credentials" to LLM Surface "keyed-guarded-chat" with caller API key "valid-caller-key"
    Then the request is rejected by the Prompt Guard
    And provider "bravo" received no chat completion requests

  Scenario: Source authentication only protects the configured LLM Surface route
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "alpha-chat" for route "/chat"
    And the operator has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When the caller sends a chat completion request to LLM Surface "alpha-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request

  Scenario: Source authentication rejects an unauthenticated caller before Prompt Guard evaluation
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-guarded-chat" for route "/keyed-guarded-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-guarded-chat" requires "API Key" source authentication using secret "caller-api-keys"
    And LLM Surface "keyed-guarded-chat" uses Prompt Guard to reject prompts matching "leak secret"
    When the caller sends chat prompt "Please leak secret credentials" to LLM Surface "keyed-guarded-chat"
    Then the caller is rejected by source authentication
    And provider "bravo" received no chat completion requests

  Scenario: A chat completion request sent to the discovery path of an LLM Surface still requires caller credentials
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-chat" for route "/keyed-chat" targeting provider "bravo" as a Custom OpenAI-compatible endpoint
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When the caller sends a chat completion request to the discovery path of LLM Surface "keyed-chat" without caller credentials
    Then the caller is rejected by source authentication
    And provider "bravo" received no chat completion requests

  @wip
  Scenario: Caller with a managed API key issued for an LLM Surface can invoke it
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "managed-chat" for route "/managed-chat"
    And LLM Surface "managed-chat" requires its own managed API keys
    And the operator has issued a managed API key for LLM Surface "managed-chat"
    When the caller sends a chat completion request to LLM Surface "managed-chat" with that managed API key
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" did not receive header "X-API-Key"

  @wip
  Scenario: Caller with a revoked managed API key cannot invoke an LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "managed-chat" for route "/managed-chat"
    And LLM Surface "managed-chat" requires its own managed API keys
    And the operator has issued a managed API key for LLM Surface "managed-chat"
    And the operator has revoked that managed API key
    When the caller sends a chat completion request to LLM Surface "managed-chat" with that managed API key
    Then the caller is rejected by source authentication
    And provider "bravo" received no chat completion requests
