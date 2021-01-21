const fs = require('fs');

const namespace = 'namespace light_saber\n{\n'

const path = 'saber/light_saber';
const files = fs.readdirSync(path);

files.forEach(e => {
    let fileName = e.split('.')[0];
    let fileExt = e.split('.')[1];

    let filePath = path + '/' + e;

    if (['h', 'cpp', 'c', 'hpp'].includes(fileExt)) {
        let file = fs.readFileSync(filePath).toString();

        file = file.replace(/((?:#include .+\n+)+)/, '$1\n' + namespace);

        file += '\n}\n';

        if (fileExt == 'c') {
            fs.unlinkSync(filePath)
            e = fileName + '.' + 'cpp';

            filePath = path + '/' + e
        }

        fs.writeFileSync(filePath, file);

        console.log(`${e} done`);

    }
})