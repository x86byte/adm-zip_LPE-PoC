const AdmZip = require('adm-zip');
const fs = require('fs');

const archivePath = process.argv[2] || 'exploit.zip';
const targetDir = process.argv[3] || './out';

if (!fs.existsSync(archivePath)) {
    console.error(`Archive not found: ${archivePath}`);
    process.exit(1);
}

const zip = new AdmZip(archivePath);
zip.extractAllTo(targetDir, true, true);
console.log(`Extracted ${archivePath} into ${targetDir}`);
