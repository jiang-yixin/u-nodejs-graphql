const path = require('path');
const fs = require('fs');

const clearImage = filePath => {
    fpath = path.join(__dirname, '..', filePath);
    fs.unlink(fpath, err => console.log(err));
};

exports.clearImage = clearImage;