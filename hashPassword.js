const bcrypt = require('bcrypt');
const saltRounds = 10;
const readline = require('readline');

async function hashPassword(password) {
    try {
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('Parola hash-uita:', hashedPassword);
        return hashedPassword;
    } catch (error) {
        console.error('Error hashing password:', error);
        throw error;
    }
}

hashPassword('member').then(hashedPassword => {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question('Apasă Enter pentru a închide programul...', (answer) => {
        rl.close();
    });
}).catch(err => {
    console.error('Eroare la hash-uirea parolei:', err);
});
