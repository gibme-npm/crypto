const version = require('../package.json').version;
const exec = require('child_process').exec;

exec(`yarn version --no-commit-hooks --no-git-tag-version --new-version ${version}`, {
    cwd: process.cwd() + '/browser'
}, (error, stdout, stderr) => {
    process.stdout.write(stdout.toString());
    process.stderr.write(stderr.toString());
    if (error) {
        return console.error(error.toString());
    }
});
