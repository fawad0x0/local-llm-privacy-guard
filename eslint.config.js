const js = require("@eslint/js");
const globals = require("globals");

module.exports = [
  { ignores: ["node_modules/**", "dist/**"] },
  js.configs.recommended,
  {
    files: ["src/**/*.js", "popup.js", "options.js", "background.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: { ...globals.browser, ...globals.webextensions, importScripts: "readonly" }
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }],
      "no-empty": ["error", { allowEmptyCatch: true }],
      "no-control-regex": "off",
      "no-useless-escape": "off",
      "no-misleading-character-class": "off",
      "no-labels": ["error", { allowLoop: true }]
    }
  },
  {
    files: ["tests/**/*.js", "scripts/**/*.js", "eslint.config.js"],
    languageOptions: { ecmaVersion: 2022, sourceType: "commonjs", globals: { ...globals.node } },
    rules: { "no-unused-vars": ["error", { caughtErrors: "none" }] }
  },
  {
    files: ["tests/e2e/**/*.js"],
    languageOptions: { globals: { ...globals.node, ...globals.browser, ...globals.webextensions } }
  }
];
