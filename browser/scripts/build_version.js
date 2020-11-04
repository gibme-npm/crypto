const version = require('../package.json').version;
const writeFileSync = require('fs').writeFileSync;
writeFileSync('./src/version.ts', [
    '// this file is updated via the package prepare script',
    `export const version = '${version}';`
].join('\n') + '\n');
