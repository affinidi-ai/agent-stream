Feature: Surface ownership
  Only the user who published a Surface, or an administrator, can change or delete it.

  Scenario: A base user cannot remove source authentication from another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When base user "bob" removes source authentication from LLM Surface "keyed-chat"
    Then the Surface change is forbidden
    And LLM Surface "keyed-chat" still requires source authentication

  Scenario: A base user cannot delete another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "alpha-chat" for route "/alpha-chat"
    When base user "bob" deletes LLM Surface "alpha-chat"
    Then the Surface change is forbidden
    And LLM Surface "alpha-chat" is still published

  Scenario: A base user can remove source authentication from their own LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When base user "alice" removes source authentication from LLM Surface "keyed-chat"
    Then the Surface change succeeds
    And LLM Surface "keyed-chat" no longer requires source authentication

  Scenario: An administrator can remove source authentication from another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "keyed-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When administrator "ada" removes source authentication from LLM Surface "keyed-chat"
    Then the Surface change succeeds
    And LLM Surface "keyed-chat" no longer requires source authentication

  Scenario: An administrator can delete another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "alpha-chat" for route "/alpha-chat"
    When administrator "ada" deletes LLM Surface "alpha-chat"
    Then the Surface change succeeds
    And LLM Surface "alpha-chat" is no longer published

  Scenario: A base user cannot add a variant to another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    When base user "bob" adds variant "open" to LLM Surface "keyed-chat"
    Then the Surface change is forbidden
    And LLM Surface "keyed-chat" has no variants

  Scenario: A base user can add a variant to their own LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    When base user "alice" adds variant "open" to LLM Surface "keyed-chat"
    Then the Surface change succeeds
    And LLM Surface "keyed-chat" has variant "open"

  Scenario: A base user cannot make a variant the default of another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And base user "alice" has added variant "open" to LLM Surface "keyed-chat"
    When base user "bob" makes variant "open" the default of LLM Surface "keyed-chat"
    Then the Surface change is forbidden
    And LLM Surface "keyed-chat" still uses its base configuration by default

  Scenario: A Surface is owned by its publisher whatever the request names
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "bob" has published LLM Surface "bobs-chat" for route "/bobs-chat" naming "alice" as its owner
    When base user "alice" deletes LLM Surface "bobs-chat"
    Then the Surface change is forbidden
    And LLM Surface "bobs-chat" is still published
    And LLM Surface "bobs-chat" is owned by base user "bob"

  Scenario: A base user cannot rename a variant of another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And base user "alice" has added variant "open" to LLM Surface "keyed-chat"
    When base user "bob" renames variant "open" of LLM Surface "keyed-chat" to "taken"
    Then the Surface change is forbidden
    And variant "open" of LLM Surface "keyed-chat" is still named "open"

  Scenario: A base user cannot delete a variant of another user's LLM Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And base user "alice" has added variant "open" to LLM Surface "keyed-chat"
    When base user "bob" deletes variant "open" of LLM Surface "keyed-chat"
    Then the Surface change is forbidden
    And LLM Surface "keyed-chat" has variant "open"

  Scenario: A base user cannot publish another user's LLM Surface in their IDE Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "alpha-chat" for route "/alpha-chat"
    And base user "bob" has published IDE Surface "bobs-tools" for route "/bobs-tools"
    When base user "bob" publishes LLM Surface "alpha-chat" in IDE Surface "bobs-tools" as model "alpha"
    Then the Surface change is forbidden
    And IDE Surface "bobs-tools" publishes no models

  Scenario: A base user can publish their own LLM Surface in their IDE Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "bob" has published LLM Surface "bobs-chat" for route "/bobs-chat"
    And base user "bob" has published IDE Surface "bobs-tools" for route "/bobs-tools"
    When base user "bob" publishes LLM Surface "bobs-chat" in IDE Surface "bobs-tools" as model "bobs"
    Then the Surface change succeeds
    And IDE Surface "bobs-tools" publishes LLM Surface "bobs-chat" as model "bobs"
