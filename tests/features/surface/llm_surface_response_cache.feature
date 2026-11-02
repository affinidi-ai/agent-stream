Feature: LLM Surface response caching
  Operators cache successful buffered responses to avoid repeated provider calls while preserving request and variant isolation.

  Scenario: Repeated exact request is served from cache
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" uses an exact response cache for 60 seconds
    And the caller has cached chat prompt "How do I rotate a key?" through LLM Surface "cached-chat"
    When the caller sends chat prompt "How do I rotate a key?" to LLM Surface "cached-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And the response reports a cache hit
    And provider "bravo" received 1 chat completion request

  Scenario: Different requests use separate cache entries
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" uses an exact response cache for 60 seconds
    And the caller has cached chat prompt "How do I rotate a key?" through LLM Surface "cached-chat"
    When the caller sends chat prompt "How do I revoke a key?" to LLM Surface "cached-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And the response reports a cache miss
    And provider "bravo" received 2 chat completion requests

  Scenario: Expired response is fetched from the provider again
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" uses an exact response cache for 1 second
    And the caller has cached chat prompt "How do I rotate a key?" through LLM Surface "cached-chat"
    And the cache entry has expired
    When the caller sends chat prompt "How do I rotate a key?" to LLM Surface "cached-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And the response reports a cache miss
    And provider "bravo" received 2 chat completion requests

  Scenario: Updating a Surface invalidates its cached responses
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" uses an exact response cache for 60 seconds
    And the caller has cached chat prompt "How do I rotate a key?" through LLM Surface "cached-chat"
    And the operator has updated LLM Surface "cached-chat" to target provider "charlie"
    When the caller sends chat prompt "How do I rotate a key?" to LLM Surface "cached-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And the response reports a cache miss
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received 1 chat completion request

  Scenario: Base Surface and variant use separate cache entries
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" uses an exact response cache for 60 seconds
    And LLM Surface "cached-chat" has variant "premium" targeting provider "charlie"
    And the caller has cached chat prompt "How do I rotate a key?" through LLM Surface "cached-chat"
    When the caller sends chat prompt "How do I rotate a key?" to variant "premium" of LLM Surface "cached-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And the response reports a cache miss
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received 1 chat completion request

  Scenario: Semantically similar request is served from cache
    Given provider "bravo" can return chat completions
    And embedding provider "vector" returns the same meaning for similar prompts
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" uses a semantic response cache with embedding provider "vector"
    And the caller has cached chat prompt "How do I rotate a key?" through LLM Surface "cached-chat"
    When the caller sends chat prompt "What is the way to rotate a key?" to LLM Surface "cached-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And the response reports a cache hit
    And provider "bravo" received 1 chat completion request

  # A Surface that forwards each caller's own token answers as that caller (a
  # Microsoft 365 Copilot Surface grounds answers on the user's own mail and
  # files), so the same prompt from another caller must not get the cached
  # answer. The second caller's miss shows the entries are separate; the first
  # caller's later hit shows the cache still works for each caller.
  Scenario: Each caller of an identity pass-through Surface gets only their own cached response
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" requires JWT source authentication for issuer "https://issuer.example.test" and audience "agent-stream"
    And LLM Surface "cached-chat" forwards caller tokens to its provider
    And LLM Surface "cached-chat" uses an exact response cache for 60 seconds
    And caller "alice" has sent chat prompt "What is on my calendar?" to LLM Surface "cached-chat" with their own JWT
    And caller "bob" has sent chat prompt "What is on my calendar?" to LLM Surface "cached-chat" with their own JWT
    When caller "alice" sends chat prompt "What is on my calendar?" to LLM Surface "cached-chat" with their own JWT
    Then the caller receives a successful chat completion from provider "bravo"
    And the response reports a cache hit
    And provider "bravo" received 2 chat completion requests

  Scenario: Each caller of an identity pass-through Surface gets only their own cached streamed response
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "cached-chat" for route "/cached-chat" targeting provider "bravo"
    And LLM Surface "cached-chat" requires JWT source authentication for issuer "https://issuer.example.test" and audience "agent-stream"
    And LLM Surface "cached-chat" forwards caller tokens to its provider
    And LLM Surface "cached-chat" uses an exact response cache for 60 seconds
    And caller "alice" has streamed chat prompt "What is on my calendar?" from LLM Surface "cached-chat" with their own JWT
    And caller "bob" has streamed chat prompt "What is on my calendar?" from LLM Surface "cached-chat" with their own JWT
    When caller "alice" requests streamed chat prompt "What is on my calendar?" from LLM Surface "cached-chat" with their own JWT
    Then the caller receives an OpenAI-compatible event stream containing "Hello from bravo"
    And the response reports a cache hit
    And provider "bravo" received 2 chat completion requests
