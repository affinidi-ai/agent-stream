/**
 * JSON Schema generation utilities
 * Protocol-aware logic for deriving JSON schemas from payload structures
 */

/**
 * Protocol type for routing schema extraction
 */
export type ProtocolType = 'a2a' | 'mcp' | 'ucp' | 'unknown';

/**
 * Protocol-specific identity extension URIs
 */
const PROTOCOL_IDENTITY_EXTENSIONS = {
  a2a: 'https://fabric.affinidi.io/extensions/agent-identity/v1',
  ucp: 'https://fabric.affinidi.io/extensions/agent-identity/v1',
};

/**
 * Generate a JSON schema from a JSON payload
 * Inspects the payload structure and generates a matching schema
 */
export const generateSchemaFromPayload = (payload: any): string => {
  const inferType = (value: any): string => {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
  };

  const buildSchemaFromObject = (obj: any): any => {
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
      return { type: inferType(obj) };
    }

    const properties: any = {};
    const required: string[] = [];

    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        const firstItem = value.length > 0 ? value[0] : null;
        properties[key] = {
          type: 'array',
          items:
            typeof firstItem === 'object' && firstItem !== null && !Array.isArray(firstItem)
              ? buildSchemaFromObject(firstItem)
              : { type: inferType(firstItem) },
        };
      } else if (typeof value === 'object' && value !== null) {
        properties[key] = buildSchemaFromObject(value);
      } else {
        properties[key] = { type: inferType(value) };
      }
      required.push(key);
    }

    return {
      type: 'object',
      properties,
      required,
    };
  };

  const schema = buildSchemaFromObject(payload);
  return JSON.stringify(schema, null, 2);
};

/**
 * Detect protocol type from payload structure
 */
const detectProtocol = (payload: any): ProtocolType => {
  if (!payload || typeof payload !== 'object') return 'unknown';

  // MCP: Has jsonrpc and either 'method' field or _meta field
  if (payload.jsonrpc === '2.0' && (payload.method || payload._meta)) {
    // Check if it has MCP-specific patterns
    if (payload._meta || payload.method?.includes('/')) {
      return 'mcp';
    }
  }

  // A2A: JSON-RPC 2.0 with params.message structure
  if (payload.jsonrpc === '2.0' && payload.params?.message) {
    return 'a2a';
  }

  return 'unknown';
};

/**
 * Extract identity data from A2A/UCP protocol payload
 * These protocols use JSON-RPC 2.0 with params.message.metadata structure
 */
const extractIdentityFromJsonRpcProtocol = (
  payload: any,
  fieldName: string,
  protocol: ProtocolType
): any => {
  // Get the extension URI for this protocol
  const extensionUri =
    PROTOCOL_IDENTITY_EXTENSIONS[protocol as keyof typeof PROTOCOL_IDENTITY_EXTENSIONS];
  if (!extensionUri) return null;

  // Try params.message.metadata first (JSON-RPC wrapped format)
  const metadata =
    payload.params?.message?.metadata || payload.message?.metadata || payload.metadata;

  if (metadata && typeof metadata === 'object') {
    // Look for the extension URI
    const extensionData = metadata[extensionUri];
    if (extensionData && typeof extensionData === 'object') {
      // Extract the identity field from within the extension
      return extensionData[fieldName] || null;
    }

    // Fallback: check if the field exists directly in metadata
    if (metadata[fieldName]) {
      return metadata[fieldName];
    }
  }

  return null;
};

/**
 * Extract identity data from MCP protocol payload
 * MCP uses _meta field for metadata
 */
const extractIdentityFromMcp = (payload: any, fieldName: string): any => {
  if (payload._meta && typeof payload._meta === 'object') {
    return payload._meta[fieldName] || null;
  }
  return null;
};

/**
 * Extract agentIdentity schema from a payload in the format needed for channel configuration
 * Returns a schema formatted for the channel edit request schema field
 * @param payload - The payload to extract the identity schema from
 * @param fieldName - The name of the identity field (defaults to 'agentIdentity')
 * @param protocol - Optional protocol type (will auto-detect if not provided)
 */
export const extractAgentIdentitySchema = (
  payload: any,
  fieldName: string = 'agentIdentity',
  protocol?: ProtocolType
): string => {
  // Auto-detect protocol if not provided
  const detectedProtocol = protocol || detectProtocol(payload);

  console.log(`[Schema Extraction] Protocol: ${detectedProtocol}, Field: ${fieldName}`);

  // Extract identity data based on protocol
  let identityData = null;

  switch (detectedProtocol) {
    case 'a2a':
    case 'ucp':
      identityData = extractIdentityFromJsonRpcProtocol(payload, fieldName, detectedProtocol);
      console.log(
        `[Schema Extraction] ${detectedProtocol.toUpperCase()} - Identity found:`,
        !!identityData
      );
      break;

    case 'mcp':
      identityData = extractIdentityFromMcp(payload, fieldName);
      console.log(`[Schema Extraction] MCP - Identity found:`, !!identityData);
      break;

    default:
      // Fallback: try generic extraction
      console.log('[Schema Extraction] Unknown protocol - trying generic extraction');
      if (payload && typeof payload === 'object' && payload[fieldName]) {
        identityData = payload[fieldName];
      }
      break;
  }

  // If no identity data found, return empty schema
  if (!identityData) {
    return JSON.stringify(
      {
        type: 'object',
        properties: {
          [fieldName]: {
            type: 'object',
            properties: {},
          },
        },
        required: [] as string[],
      },
      null,
      2
    );
  }

  // Build schema from agentIdentity
  const inferType = (value: any): string => {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
  };

  const buildSchemaFromObject = (obj: any): any => {
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
      return { type: inferType(obj) };
    }

    const properties: any = {};
    const required: string[] = [];

    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        const firstItem = value.length > 0 ? value[0] : null;
        properties[key] = {
          type: 'array',
          items:
            typeof firstItem === 'object' && firstItem !== null && !Array.isArray(firstItem)
              ? buildSchemaFromObject(firstItem)
              : { type: inferType(firstItem) },
        };
      } else if (typeof value === 'object' && value !== null) {
        properties[key] = buildSchemaFromObject(value);
      } else {
        properties[key] = { type: inferType(value) };
      }
      required.push(key);
    }

    return {
      type: 'object',
      properties,
      required,
    };
  };

  const agentIdentitySchema = buildSchemaFromObject(identityData);

  // Wrap in the channel configuration format
  const channelSchema = {
    type: 'object',
    properties: {
      [fieldName]: agentIdentitySchema,
    },
    required: [] as string[],
  };

  return JSON.stringify(channelSchema, null, 2);
};
