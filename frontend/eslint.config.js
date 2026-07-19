import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  // vite.config.online.ts is a gitignored, machine-local deployment override.
  // It must not make the repository-wide `eslint .` gate depend on a user's
  // local file contents.
  globalIgnores(['dist', 'vite.config.online.ts']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      // Our pages fetch data in useEffect via an async helper that calls
      // setState only in its .then() callback (i.e. asynchronously, never
      // synchronously inside the effect body). React 19's new
      // set-state-in-effect rule flags this pattern conservatively; the
      // pattern is the documented way to load data on mount and is safe.
      'react-hooks/set-state-in-effect': 'off',
    },
  },
])
