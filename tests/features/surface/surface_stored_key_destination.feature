Feature: Where a surface sends a stored provider key
  Choosing where a surface sends a stored provider key decides who receives the key, so only operators who may view secrets can point a keyed surface at a new endpoint; editors can still change everything else.

  Background:
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And base user "editor@example.test" has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And LLM Surface "keyed-chat" sends the operator's provider key from secret "operator-key"

  Scenario: An editor without access to secrets cannot send a stored provider key to another provider
    Given human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" points LLM Surface "keyed-chat" at provider "charlie"
    Then the surface change is refused because it needs access to secrets
    And LLM Surface "keyed-chat" is still saved with provider "bravo"

  Scenario: An editor without access to secrets can still change a surface that sends a stored provider key
    Given human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" renames LLM Surface "keyed-chat" to "Renamed chat"
    Then the surface change is saved and LLM Surface "keyed-chat" is named "Renamed chat"

  Scenario: An access token without access to secrets cannot send a stored provider key to another provider
    Given human user "admin@example.test" is an administrator using an access token limited to "pipes.view, pipes.edit"
    When human user "admin@example.test" points LLM Surface "keyed-chat" at provider "charlie"
    Then the surface change is refused because it needs access to secrets
    And LLM Surface "keyed-chat" is still saved with provider "bravo"

  Scenario: An editor without access to secrets cannot send a stored provider key elsewhere through a variant
    Given LLM Surface "keyed-chat" has disabled variant "alt" targeting provider "bravo"
    And human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" points variant "alt" of LLM Surface "keyed-chat" at provider "charlie" with provider key "operator-key"
    Then the surface change is refused because it needs access to secrets

  Scenario: An operator who may view secrets sends a stored provider key elsewhere through a variant
    Given LLM Surface "keyed-chat" has disabled variant "alt" targeting provider "bravo"
    And human user "admin@example.test" may view secrets
    When human user "admin@example.test" points variant "alt" of LLM Surface "keyed-chat" at provider "charlie" with provider key "operator-key"
    Then the variant change is saved

  Scenario: An operator who may view secrets sends a stored provider key to another provider
    Given human user "admin@example.test" may view secrets
    When human user "admin@example.test" points LLM Surface "keyed-chat" at provider "charlie"
    Then the surface change is saved and LLM Surface "keyed-chat" calls provider "charlie"
