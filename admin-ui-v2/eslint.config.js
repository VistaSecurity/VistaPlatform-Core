// ESLint flat config for admin-ui-v2 (platform admin console).
// Rules live in the shared monorepo base — see ../eslint.config.base.mjs.
import baseConfig from '../eslint.config.base.mjs';

export default baseConfig(import.meta.dirname);
