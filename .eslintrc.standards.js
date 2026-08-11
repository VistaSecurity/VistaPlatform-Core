module.exports = {
  rules: {
    // Basic naming conventions
    'camelcase': ['error', { 'properties': 'never' }],

    // API URL naming standards
    'no-restricted-globals': [
      'error',
      {
        name: 'API_BASE_URL',
        message: 'Use VITE_API_URL environment variable instead of hardcoded API_BASE_URL',
      },
    ],

    // Consistent file naming
    'no-console': 'warn',
    'no-debugger': 'error',
    'no-unused-vars': 'warn',
  },
  languageOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    globals: {
      console: 'readonly',
      process: 'readonly',
      Buffer: 'readonly',
      __dirname: 'readonly',
      __filename: 'readonly',
      global: 'readonly',
      module: 'readonly',
      require: 'readonly',
      exports: 'readonly',
    },
  },
};
