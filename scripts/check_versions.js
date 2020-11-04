const main = require('../package.json').version;
const browser = require('../browser/package.json').version;

if (main !== browser) {
    process.exit(1);
} else {
    process.exit(0);
}
