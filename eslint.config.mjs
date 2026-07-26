import { defineConfig, globalIgnores } from "eslint/config";
import { fixupConfigRules } from "@eslint/compat";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...fixupConfigRules(nextVitals),
  ...fixupConfigRules(nextTs),
  {
    rules: {
      // Allow setState in effects for initial data fetching and derived state resets.
      // These are common, valid React patterns (data fetch on mount, reset on prop change).
      "react-hooks/set-state-in-effect": "warn",
      // Allow unused vars prefixed with _ (standard destructuring discard pattern)
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          destructuredArrayIgnorePattern: "^_",
        },
      ],
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Generated artifacts (also in .gitignore) — never source to lint.
    "playwright-report/**",
    "test-results/**",
    ".test-sandbox/**",
    "coverage/**",
    "sbom/**",
  ]),
]);

export default eslintConfig;
