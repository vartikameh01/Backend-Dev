const fs = require('fs');
const path = require('path');
const command = process.argv[2];
const fileName = process.argv[3];

if (command === 'read') {
    // Check if file exists and is readable
    fs.access(fileName, fs.constants.R_OK, (err) => {
        if (err) {
            console.error('Error: Cannot read file. File may not exist or you lack read permissions.');
            return;
        }

        fs.readFile(fileName, 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading file:', err.message);
                return;
            }
            console.log('File Content:');
            console.log(data);
        });
    });
} else if (command === 'write') {
    const content = process.argv[4];

    // Check if parent directory is writable
    const dirPath = path.dirname(fileName);

    fs.access(dirPath, fs.constants.W_OK, (err) => {
        if (err) {
            console.error('Error: Cannot write to this location. You may lack write permissions.');
            return;
        }

        fs.writeFile(fileName, content, 'utf8', (err) => {
            if (err) {
                console.error('Error writing file:', err.message);
                return;
            }
            console.log(`File "${fileName}" written successfully!`);
        });
    });
} else if (command === 'copy') {
    const destination = process.argv[4];

    // Check if source file is readable
    fs.access(fileName, fs.constants.R_OK, (err) => {
        if (err) {
            console.error('Error: Cannot read source file. File may not exist or you lack read permissions.');
            return;
        }

        // Check if destination directory is writable
        const destDir = path.dirname(destination);
        fs.access(destDir, fs.constants.W_OK, (err) => {
            if (err) {
                console.error('Error: Cannot write to destination. You may lack write permissions.');
                return;
            }

            const readStream = fs.createReadStream(fileName);
            const writeStream = fs.createWriteStream(destination);
            readStream.pipe(writeStream);
            readStream.on('error', err => console.error('Read error:', err.message));
            writeStream.on('error', err => console.error('Write error:', err.message));
            writeStream.on('finish', () => console.log(`File copied to "${destination}" successfully!`));
        });
    });
} else if (command === 'delete') {
    // Check if file exists and is writable (required to delete)
    fs.access(fileName, fs.constants.W_OK, (err) => {
        if (err) {
            console.error('Error: Cannot delete file. File may not exist or you lack write permissions.');
            return;
        }

        fs.unlink(fileName, (err) => {
            if (err) {
                console.error('Error deleting file:', err.message);
                return;
            }
            console.log(`File "${fileName}" deleted successfully!`);
        });
    });
} else if (command === 'list') {
    // Agar user folder path na de, to current folder use karo
    const dirPath = fileName || '.';

    // Check if directory exists and is readable
    fs.access(dirPath, fs.constants.R_OK, (err) => {
        if (err) {
            console.error('Error: Cannot read directory. Directory may not exist or you lack read permissions.');
            return;
        }

        fs.readdir(dirPath, (err, files) => {
            if (err) {
                console.error('Error reading directory:', err.message);
                return;
            }

            console.log(`Contents of "${dirPath}":`);
            files.forEach(file => console.log(file));
        });
    });
} else {
    console.log(`
Usage: app.js <command> [arguments]

Commands:
  read <file>              Read and display file contents
  write <file> <content>   Write content to a file
  copy <source> <dest>     Copy a file to a new location
  delete <file>            Delete a file
  list [directory]         List contents of a directory (default: current)

Options:
  -h, --help               Show this help message
`);
    process.exit(0);
}

