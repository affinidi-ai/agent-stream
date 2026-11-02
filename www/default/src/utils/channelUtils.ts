/**
 * Utility functions for surface schema editing.
 */

export interface SchemaProperty {
  name: string;
  type: string;
  required: boolean;
  xIdentity: boolean;
  level: number;
  parent?: number;
  collapsed?: boolean;
  value?: string;
  validationRule?: {
    type: string;
    value: string;
    elementType?: string;
    values?: string;
    min?: string;
    max?: string;
  };
}

/**
 * Count x-identity fields in a schema
 */
// Helper function to count identity fields in a schema (same as ChannelsPage)
export const countXIdentityFields = (schema: any): number => {
  if (!schema) return 0;

  let count = 0;

  const traverse = (obj: any) => {
    if (!obj || typeof obj !== 'object') return;

    // Check if this property has x-identity marker
    if (obj['x-identity'] === true) {
      count++;
    }

    // Traverse properties in schema (only properties, not other object values)
    if (obj.properties) {
      Object.values(obj.properties).forEach(prop => traverse(prop));
    }

    // Traverse items in arrays
    if (obj.items) {
      traverse(obj.items);
    }

    // Traverse specific JSON Schema composition keywords
    if (obj.allOf) obj.allOf.forEach(traverse);
    if (obj.anyOf) obj.anyOf.forEach(traverse);
    if (obj.oneOf) obj.oneOf.forEach(traverse);
  };

  traverse(schema);
  return count;
};

// Helper function to count all validation rules (both schema-based and custom rules)
export const countValidationRules = (extensionRules: any): number => {
  if (!extensionRules) return 0;

  let count = 0;

  // Count custom validation rules from the rules array
  if (extensionRules.rules && Array.isArray(extensionRules.rules)) {
    count += extensionRules.rules.length;
  }

  // Count schema-based validation rules with validation type
  if (extensionRules.json_schema) {
    const traverse = (obj: any, path: string = '') => {
      if (!obj || typeof obj !== 'object') return;

      // Skip root level and only check actual property definitions
      if (path && !path.includes('.properties.') && !path.includes('.items')) {
        // Check if this property has a validationRule.type
        if (obj.validationRule && obj.validationRule.type) {
          count++;
        } else {
          // Check for direct validation patterns that would generate validationRule.type
          // Only count actual validation constraints, not structural elements
          if (
            obj.const !== undefined ||
            (obj.enum && Array.isArray(obj.enum)) ||
            obj.pattern ||
            obj.minimum !== undefined ||
            obj.maximum !== undefined
          ) {
            count++;
          }
        }
      }

      // Traverse nested properties
      if (obj.properties) {
        Object.entries(obj.properties).forEach(([key, prop]) =>
          traverse(prop, path ? `${path}.properties.${key}` : `properties.${key}`)
        );
      }

      // Traverse array items
      if (obj.items) {
        traverse(obj.items, `${path}.items`);
      }
    };

    traverse(extensionRules.json_schema, '');
  }

  return count;
};

/**
 * Parse fabric:// URLs and get gateway/channel IDs
 */
export const parseFabricUrl = (
  endpoint: string
): { gatewayId?: string; channelId?: string } | null => {
  if (!endpoint.startsWith('fabric://')) {
    return null;
  }

  const fabricUrl = endpoint.substring(9);
  const parts = fabricUrl.split('/');
  if (parts.length >= 2) {
    return {
      gatewayId: parts[0],
      channelId: parts[1],
    };
  }
  return null;
};

/**
 * Validate JSON schema types
 */
export const validateJsonSchemaTypes = (jsonObj: any, path: string = ''): string[] => {
  const errors: string[] = [];
  const validTypes = ['string', 'number', 'boolean', 'object', 'array'];

  const validateProperty = (obj: any, currentPath: string) => {
    if (obj && typeof obj === 'object') {
      if (obj.type !== undefined) {
        if (!validTypes.includes(obj.type)) {
          errors.push(
            `Invalid type "${obj.type}" at ${currentPath || 'root'}. Must be one of: ${validTypes.join(', ')}`
          );
        }
      }

      if (obj.properties && typeof obj.properties === 'object') {
        Object.keys(obj.properties).forEach(key => {
          const newPath = currentPath ? `${currentPath}.properties.${key}` : `properties.${key}`;
          validateProperty(obj.properties[key], newPath);
        });
      }

      if (obj.items && typeof obj.items === 'object') {
        const newPath = currentPath ? `${currentPath}.items` : 'items';
        validateProperty(obj.items, newPath);
      }
    }
  };

  validateProperty(jsonObj, path);
  return errors;
};

/**
 * Check if child property is visible based on parent collapse state
 */
export const isChildVisible = (
  childProperty: SchemaProperty,
  parentIndex: number | undefined,
  properties: SchemaProperty[]
): boolean => {
  if (parentIndex === undefined) return true;

  const parent = properties[parentIndex];
  if (!parent) return true;

  if (parent.collapsed) {
    return false;
  }

  if (parent.parent !== undefined) {
    return isChildVisible(childProperty, parent.parent, properties);
  }

  return true;
};
