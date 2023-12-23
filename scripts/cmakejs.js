const child_process = require('child_process');
const path = require('path');

const cmakejs = path.resolve(process.argv[2] ?? 'cmake-js');
const debug = process.argv[3] === 'debug';
const cmd = `${cmakejs} print-configure ${debug ? '--debug' : ''}`;

(async () => {
    const execute = async () => new Promise((resolve, reject) => {
        child_process.exec(cmd, {
            cwd: process.cwd()
        }, (error, stdout, stderr) => {
            if (error) {
                return reject(stderr);
            }

            const result = stdout.trim()
                .replace(/'/g, '"');

            return resolve(JSON.parse(result));
        });
    });

    const lines = await execute();

    const output = [];

    for (let line of lines) {
        if (line.startsWith('-D')) {
            line = line.substring(2);

            const [key, value] = line.split('=', 2);

            const values = value.split(';');

            if (values.length === 1) {
                output.push(`${key}=${value}`);
            } else {
                for (let i = 0; i < values.length; i++) {
                    output.push(`${key}=${values[i]}`);
                }
            }
        }
    }

    console.log(output.join(';'));
})();
