const existsSync = require('fs').existsSync;
const resolve = require('path').resolve;

const path = resolve(__dirname, '../.gitsource');

console.log('Checking for: %s', path);

const exists = existsSync(path);

if (exists) {
    console.log('.gitsource exists!');
    process.exit(0);
} else {
    console.log('.gitsource does not exist!');
    process.exit(1);
}
