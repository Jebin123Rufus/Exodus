import { BaseReasoner } from './baseReasoner.js';

export class InjectionReasoner extends BaseReasoner {
  constructor() {
    super('InjectionReasoner', [
      'INPUT_SOURCE', 'DATABASE_QUERY', 'DATABASE_EXECUTION', 'ORM_QUERY',
      'RAW_SQL', 'COMMAND_EXECUTION', 'QUERY_PARAMETER', 'BODY_INPUT',
      'FORM_INPUT', 'TEMPLATE_RENDER', 'XML_PARSER'
    ]);
  }
}

export class AuthenticationReasoner extends BaseReasoner {
  constructor() {
    super('AuthenticationReasoner', [
      'AUTHENTICATION', 'SESSION', 'JWT_GENERATION', 'JWT_VALIDATION',
      'OAUTH', 'OIDC', 'SAML', 'PASSWORD', 'PASSWORD_HASH',
      'COOKIE', 'MIDDLEWARE', 'SECURITY_FILTER', 'TOKEN'
    ]);
  }
}

export class AuthorizationReasoner extends BaseReasoner {
  constructor() {
    super('AuthorizationReasoner', [
      'AUTHORIZATION', 'ROLE_CHECK', 'PERMISSION_CHECK', 'OWNERSHIP_CHECK',
      'TENANT_CHECK', 'HTTP_ENDPOINT', 'HTTP_HANDLER', 'MIDDLEWARE'
    ]);
  }
}

export class FilesystemReasoner extends BaseReasoner {
  constructor() {
    super('FilesystemReasoner', [
      'FILE_READ', 'FILE_WRITE', 'FILE_DELETE', 'FILE_UPLOAD', 'FILE_DOWNLOAD',
      'PATH_CONSTRUCTION', 'DIRECTORY_ACCESS', 'DESERIALIZATION'
    ]);
  }
}

export class CryptoReasoner extends BaseReasoner {
  constructor() {
    super('CryptoReasoner', [
      'CRYPTO_API', 'HASH_FUNCTION', 'PASSWORD_HASH', 'KEY_GENERATION',
      'IV_GENERATION', 'CERTIFICATE', 'HMAC', 'ENCRYPTION', 'DECRYPTION',
      'RANDOM_GENERATOR', 'SECRET', 'API_KEY'
    ]);
  }
}

export class NetworkReasoner extends BaseReasoner {
  constructor() {
    super('NetworkReasoner', [
      'HTTP_CLIENT', 'NETWORK_REQUEST', 'URL_CONSTRUCTION', 'REDIRECT',
      'WEBSOCKET', 'SOCKET', 'GRAPHQL', 'GRPC', 'DNS', 'SMTP', 'FTP'
    ]);
  }
}

export class DependencyReasoner extends BaseReasoner {
  constructor() {
    super('DependencyReasoner', [
      'DEPENDENCY', 'PACKAGE', 'IMPORT', 'CONFIGURATION', 'ENVIRONMENT_VARIABLE',
      'FRAMEWORK_COMPONENT'
    ]);
  }
}

export class BusinessLogicReasoner extends BaseReasoner {
  constructor() {
    super('BusinessLogicReasoner', [
      'BUSINESS_ENTITY', 'CUSTOM_SECURITY_LOGIC', 'OWNERSHIP_CHECK',
      'TENANT_CHECK', 'SENSITIVE_DATA', 'HTTP_ENDPOINT'
    ]);
  }
}
