Feature: Tenant LLM Surfaces on a shared provider key
  A provider key held for the whole appliance is shared by every tenant whose LLM Surfaces spend it, and the provider keeps files, batches, vector stores and stored conversations per key. A tenant's LLM Surface on such a key runs inference only and never reads or writes what the provider stores.

  Scenario Outline: A tenant's LLM Surface on an appliance-wide provider key refuses a <operation> request
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And secret "appliance-provider-key" holds a provider key for the whole appliance
    And the operator has published LLM Surface "tenant-chat" for route "/tenant-chat" for tenant "alpha" spending provider key "appliance-provider-key"
    When the caller sends a "<operation>" request to LLM Surface "tenant-chat"
    Then the "<operation>" request is refused because the provider key is shared with other tenants
    And provider "bravo" received no "<operation>" requests

    Examples:
      | operation                            |
      | file list                            |
      | batch list                           |
      | file upload                          |
      | vector store creation                |
      | chat completion naming a stored file |

  Scenario: A tenant's LLM Surface on an appliance-wide provider key still transcribes audio
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And secret "appliance-provider-key" holds a provider key for the whole appliance
    And the operator has published LLM Surface "tenant-chat" for route "/tenant-chat" for tenant "alpha" spending provider key "appliance-provider-key"
    When the caller sends a "audio transcription" request to LLM Surface "tenant-chat"
    Then the caller receives the "audio transcription" response from provider "bravo"
    And provider "bravo" received the "audio transcription" request

  Scenario: A tenant's LLM Surface on the tenant's own provider key lists the tenant's files
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And secret "alpha-provider-key" holds a provider key for tenant "alpha"
    And the operator has published LLM Surface "tenant-chat" for route "/tenant-chat" for tenant "alpha" spending provider key "alpha-provider-key"
    When the caller sends a "file list" request to LLM Surface "tenant-chat"
    Then the caller receives the "file list" response from provider "bravo"
    And provider "bravo" received the "file list" request
