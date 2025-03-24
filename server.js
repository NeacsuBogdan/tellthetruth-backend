require('dotenv').config({ path: './connection.env' });
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const express = require('express');
const bodyParser = require('body-parser');
const { expressjwt: expressJwt } = require('express-jwt');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const QRCode = require('qrcode');
const multer = require('multer');
const { exec } = require('child_process');
const stringSimilarity = require('string-similarity');
const privateKey = fs.readFileSync('./cert/localhost.key', 'utf8');
const certificate = fs.readFileSync('./cert/localhost.crt', 'utf8');
const nodemailer = require('nodemailer');

const credentials = { key: privateKey, cert: certificate };


// Configurare transportator nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});


// Configure multer for image upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        // Unique filename: Current time + Random number + File extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueSuffix);
    }
});
const upload = multer({ storage: storage });

const key = Buffer.from(process.env.BAD_WORDS_KEY, 'hex');
const algorithm = 'aes-256-cbc';
const staticIV = Buffer.alloc(16, 0); // IV static setat la zero sau orice altă valoare constantă
const app = express();
const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET;
// Asigură-te că lungimea cheii este corectă
const QR_SECRET = Buffer.from(process.env.QR_SECRET, 'hex');  // Converteste cheia din hex într-un Buffer
if (QR_SECRET.length !== 32) {
    throw new Error("Lungimea cheii trebuie să fie de 32 de bytes pentru AES-256");
}

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors()); // Enable CORS for all routes
// Serve static files from 'uploads' directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Obținere credențiale de utilizator bazate pe rol
const getUserDatabaseCredentials = (role) => {
    switch (role) {
        case 'admin':
            return { user: process.env.ADMIN_DB_USER, password: process.env.ADMIN_DB_PASSWORD };
        case 'location_owner':
            return { user: process.env.LOCATION_OWNER_DB_USER, password: process.env.LOCATION_OWNER_DB_PASSWORD };
        case 'member':
        default:
            return { user: process.env.MEMBER_DB_USER, password: process.env.MEMBER_DB_PASSWORD };
    }
};

// Conectare la baza de date
const connectToDatabase = (credentials) => {
    return mysql.createConnection({
        host: process.env.DB_HOST,
        user: credentials.user,
        password: credentials.password,
        database: process.env.DB_DATABASE,
        timezone: 'Z' // Setează fusul orar la UTC
    });
};

const decryptBadWords = (encryptedText) => {
    try {
        const parts = encryptedText.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedData = parts.join(':');
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (error) {
        console.error('Error decrypting BAD_WORDS:', error);
        return null;
    }
};



const loadJson = (filePath) => {
    try {
        const data = fs.readFileSync(filePath, { encoding: 'utf8' });
        const jsonData = JSON.parse(data);

        // Verificăm dacă structura JSON-ului este corectă
        if (!jsonData.BAD_WORDS || !jsonData.LEET_MAP) {
            throw new Error('Invalid JSON structure');
        }

        jsonData.BAD_WORDS = decryptBadWords(jsonData.BAD_WORDS);

        return jsonData;
    } catch (error) {
        console.error('Error loading or parsing data:', error);
        return null;
    }
};

const badWordsData = loadJson(path.join(__dirname, 'encryptedBadWords.json'));



app.post('/reset-password', async (req, res) => {
  const { email } = req.body;

  const credentials = getUserDatabaseCredentials('admin'); // Folosim credențialele de admin
  const db = connectToDatabase(credentials);

  try {
    console.log('Attempting to connect to the database with admin credentials');
    db.connect(err => {
      if (err) {
        console.error('Error connecting to the database:', err);
        return res.status(500).json({ message: 'Database connection error' });
      }
      console.log('Database connection established');

      // Verifică dacă emailul există în baza de date
      db.query('SELECT * FROM UTILIZATOR WHERE Email = ?', [email], async (err, result) => {
        if (err) {
          console.error('Error querying the database:', err);
          db.end();
          return res.status(500).json({ message: 'Eroare la verificarea emailului' });
        }
        if (result.length === 0) {
          console.log('Email not found in the system');
          db.end();
          return res.status(404).json({ message: 'Emailul nu există în sistem' });
        }
        console.log('Email found in the system');

        // Generează o nouă parolă
        const newPassword = crypto.randomBytes(6).toString('hex');
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        console.log('New password generated and hashed');

        // Actualizează parola în baza de date
        db.query('UPDATE UTILIZATOR SET Parola = ? WHERE Email = ?', [hashedPassword, email], (err, result) => {
          if (err) {
            console.error('Error updating the password in the database:', err);
            db.end();
            return res.status(500).json({ message: 'Eroare la actualizarea parolei' });
          }
          console.log('Password updated in the database');

          // Trimite emailul cu noua parolă
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Resetare Parolă',
            text: `Parola ta a fost resetată. Noua parolă este: ${newPassword}`
          };

          transporter.sendMail(mailOptions, (error, info) => {
            db.end();
            if (error) {
              console.error('Error sending the email:', error);
              return res.status(500).json({ message: 'Eroare la trimiterea emailului' });
            }
            console.log('Email sent successfully');
            res.status(200).json({ message: 'Parola a fost resetată și trimisă pe email' });
          });
        });
      });
    });
  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({ message: 'Eroare la resetarea parolei', error });
  }
});

app.get('/bad-words', (req, res) => {
    if (!badWordsData) {
        return res.status(500).send('Failed to load bad words data');
    }
    const { BAD_WORDS, LEET_MAP } = badWordsData;
    res.json({ BAD_WORDS, LEET_MAP });
});

// Encrypt data
const encryptData = (text) => {
    const cipher = crypto.createCipheriv(algorithm, QR_SECRET, staticIV);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
};

const generateQRCode = async (name, address) => {
    const encryptedName = encryptData(name);
    const encryptedAddress = encryptData(address);
    const dataString = JSON.stringify({ encryptedName, encryptedAddress });
    return await QRCode.toDataURL(dataString);
};

// Function to decrypt data
function decryptData(encryptedData) {
    try {
        const { encryptedName, encryptedAddress } = JSON.parse(encryptedData);

        let decryptedName = decryptSinglePiece(encryptedName);
        let decryptedAddress = decryptSinglePiece(encryptedAddress);

        return { decryptedName, decryptedAddress };
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

// Helper function to decrypt a single piece of encrypted text
function decryptSinglePiece(encryptedText) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', QR_SECRET, staticIV);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Endpoint-ul care primește name și address, generează codul QR și îl returnează
app.post('/generate-qr', async (req, res) => {
    const { name, address } = req.body;
    if (!name || !address) {
        return res.status(400).send({ error: 'Both name and address are required.' });
    }

    try {
        const qrCodeUrl = await generateQRCode(name, address);
        res.send({ qrCodeUrl });
    } catch (error) {
        console.error('Failed to generate QR code:', error);
        res.status(500).send({ error: 'Failed to generate QR code.' });
    }
});

// Import the distance calculation function
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371e3; // Earth's radius in meters
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δφ = (lat2 - lat1) * Math.PI / 180;
    const Δλ = (lon2 - lon1) * Math.PI / 180;

    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
        Math.cos(φ1) * Math.cos(φ2) *
        Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c; // Distance in meters
}
// Adjust how you call decryptData in your route handling
app.post('/validate-qr', async (req, res) => {
    const { userLat, userLon } = req.body; // Latitude and longitude of the user

    if (!req.body.encryptedData || !userLat || !userLon) {
        return res.status(400).send({ error: 'Encrypted data and user coordinates are required.' });
    }

    try {
        const { decryptedName, decryptedAddress } = decryptData(req.body.encryptedData);

        if (decryptedName && decryptedAddress) {
            const credentials = getUserDatabaseCredentials('member');
            const db = connectToDatabase(credentials);

            await db.connect();

            const query = `SELECT Id, Latitudine, Longitudine FROM LOCATIE WHERE Nume = ? AND Adresa = ?`;
            const [results] = await db.promise().execute(query, [decryptedName, decryptedAddress]);

            if (results.length > 0) {
                const location = results[0];
                const distance = calculateDistance(userLat, userLon, location.Latitudine, location.Longitudine);

                if (distance > 50) {
                    db.end();
                    return res.status(403).send({ error: 'Nu vă aflați în proximitatea locației', distance: distance });
                }

                res.send({
                    message: 'Toate verificările au avut succes. Puteți lăsa o recenzie.',
                    locationId: location.Id,
                    distance: distance,
                    verified: true
                });
            } else {
                db.end();
                res.status(404).send({ error: 'Location not found.' });
            }
        } else {
            res.status(400).send({ error: 'Decryption failed.' });
        }
    } catch (error) {
        console.error('Failed to process QR code:', error);
        res.status(500).send({ error: 'Failed to process QR code.', details: error });
    }
});

// Register endpoint
app.post('/register', async (req, res) => {
    const { Nume, Email, Parola } = req.body;
    if (!Nume || !Email || !Parola) {
        return res.status(400).send('Missing fields');
    }

    const credentials = getUserDatabaseCredentials('member');
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        // Verifică dacă emailul există deja
        const checkEmailQuery = 'SELECT Email FROM UTILIZATOR WHERE Email = ?';
        const [emailExists] = await db.promise().query(checkEmailQuery, [Email]);

        if (emailExists.length > 0) {
            return res.status(409).send('Emailul este deja inregistrat de catre alt utilizator!');
        }

        // Dacă emailul nu există, continuă cu inserarea
        const hashedPassword = await bcrypt.hash(Parola, saltRounds);
        const insertQuery = 'INSERT INTO UTILIZATOR (Nume, Email, Parola) VALUES (?, ?, ?)';
        await db.promise().query(insertQuery, [Nume, Email, hashedPassword]);
        res.status(201).send('Inregistrarea a avut succes!');
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Server error');
    } finally {
        if (db && db.end) {
            db.end(); // Asigură-te că închizi conexiunea doar dacă aceasta nu a fost închisă anterior
        }
    }
});

// Login endpoint
app.post('/login', (req, res) => {
    const { Email, Parola } = req.body;
    const credentials = getUserDatabaseCredentials('member'); // presupunem că toți sunt 'member' la autentificare
    const db = connectToDatabase(credentials);

    db.connect(err => {
        if (err) {
            console.error('Error connecting to the database:', err);
            return res.status(500).send('Database connection error');
        }

        db.query('SELECT * FROM UTILIZATOR WHERE Email = ?', [Email], async (error, results) => {
            db.end();
            if (error) {
                console.error('Error fetching user:', error);
                return res.status(500).send('Error accessing database');
            }
            if (results.length === 0) {
                return res.status(404).send('Utilizatorul nu a fost gasit');
            }

            const user = results[0];
            const isPasswordValid = await bcrypt.compare(Parola, user.Parola);

            if (!isPasswordValid) {
                return res.status(401).send('Autentificare esuata!');
            }

            const token = jwt.sign({ id: user.Id, role: user.Rol }, JWT_SECRET, { expiresIn: '1d' });

            res.send({ token, userId: user.Id });
        });
    });
});

// Verificare token middleware
const verifyToken = expressJwt({
    secret: JWT_SECRET,
    algorithms: ["HS256"]
});

app.get('/verify-token', verifyToken, (req, res) => {
    const credentials = getUserDatabaseCredentials('member'); // presupunem că toți sunt 'member'
    const db = connectToDatabase(credentials);

    db.connect(err => {
        if (err) {
            console.error('Error connecting to the database:', err);
            return res.status(500).send('Database connection error');
        }

        const userId = req.auth.id;

        // Prima interogare pentru a prelua detaliile utilizatorului, inclusiv emailul
        db.query('SELECT Id, Nume, Email, Rol FROM UTILIZATOR WHERE Id = ?', [userId], (error, userResults) => {
            if (error) {
                db.end();
                console.error('Error fetching user:', error);
                return res.status(500).send('Error accessing database');
            }
            if (userResults.length === 0) {
                db.end();
                return res.status(404).send('User not found');
            }

            const user = userResults[0];

            // A doua interogare pentru a prelua ID-urile locațiilor favorite
            db.query('SELECT Id_Locatie FROM LOCATII_FAVORITE WHERE Id_Utilizator = ?', [userId], (error, favoriteResults) => {
                db.end();
                if (error) {
                    console.error('Error fetching favorite locations:', error);
                    return res.status(500).send('Error accessing database');
                }

                const favoriteLocationIds = favoriteResults.map(row => row.Id_Locatie);

                res.send({
                    id: user.Id,
                    name: user.Nume,
                    email: user.Email, // Adăugat email-ul utilizatorului în răspuns
                    role: user.Rol,
                    favoriteLocationIds: favoriteLocationIds
                });
            });
        });
    });
});


app.post('/update-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Current password and new password are required.' });
  }

  const credentials = getUserDatabaseCredentials('admin');
  const db = connectToDatabase(credentials);

  try {
    db.connect(err => {
      if (err) {
        console.error('Error connecting to the database:', err);
        return res.status(500).json({ message: 'Database connection error' });
      }

      const userId = req.auth.id;

      db.query('SELECT Parola FROM UTILIZATOR WHERE Id = ?', [userId], async (error, results) => {
        if (error) {
          db.end();
          return res.status(500).json({ message: 'Error accessing database' });
        }

        if (results.length === 0) {
          db.end();
          return res.status(404).json({ message: 'User not found' });
        }

        console.log('User password fetched successfully');

        const hashedCurrentPassword = results[0].Parola;

        const match = await bcrypt.compare(currentPassword, hashedCurrentPassword);
        if (!match) {
          db.end();
          return res.status(400).json({ message: 'Current password is incorrect' });
        }


        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        db.query('UPDATE UTILIZATOR SET Parola = ? WHERE Id = ?', [hashedNewPassword, userId], (error, result) => {
          db.end();
          if (error) {
            return res.status(500).json({ message: 'Error updating password' });
          }

          res.status(200).json({ message: 'Password updated successfully' });
        });
      });
    });
  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({ message: 'Unexpected error occurred' });
  }
});
app.post('/update-email', verifyToken, (req, res) => {
  const { newEmail } = req.body;

  if (!newEmail) {
    return res.status(400).json({ message: 'New email is required.' });
  }

  const credentials = getUserDatabaseCredentials('admin');
  const db = connectToDatabase(credentials);

  try {
    db.connect(err => {
      if (err) {
        console.error('Error connecting to the database:', err);
        return res.status(500).json({ message: 'Database connection error' });
      }

      const userId = req.auth.id;

      db.query('UPDATE UTILIZATOR SET Email = ? WHERE Id = ?', [newEmail, userId], (error, result) => {
        db.end();
        if (error) {
          console.error('Error updating email:', error);
          return res.status(500).json({ message: 'Error updating email' });
        }

        res.status(200).json({ message: 'Email updated successfully' });
      });
    });
  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({ message: 'Unexpected error occurred' });
  }
});

app.post('/delete-account', verifyToken, async (req, res) => {
  const credentials = getUserDatabaseCredentials('admin');
  const db = connectToDatabase(credentials);

  try {
    db.connect(async (err) => {
      if (err) {
        console.error('Error connecting to the database:', err);
        return res.status(500).json({ message: 'Database connection error' });
      }

      const userId = req.auth.id;


      // Start a transaction
      db.beginTransaction(async (err) => {
        if (err) {
          console.error('Error starting transaction:', err);
          db.end();
          return res.status(500).json({ message: 'Error starting transaction' });
        }

        try {
          // Get user reviews
          const [reviews] = await db.promise().query('SELECT Id FROM FACE_O_RECENZIE WHERE Id_Utilizator = ?', [userId]);

          // Get user reports
          const [reviewReports] = await db.promise().query('SELECT Id_Recenzie FROM RAPORTEAZA_RECENZIE WHERE Id_Utilizator = ?', [userId]);
          const [locationReports] = await db.promise().query('SELECT Id_Locatie FROM RAPORTEAZA_LOCATIE WHERE Id_Utilizator = ?', [userId]);

          // Get locations uploaded by the user
          const [locations] = await db.promise().query('SELECT Id FROM LOCATIE WHERE Id_Proprietar = ?', [userId]);

          // Delete images and categories associated with these locations
          for (const location of locations) {
            // Get images for the location
            const [images] = await db.promise().query('SELECT Cale_Imagine FROM IMAGINI_LOCATIE WHERE Id_Locatie = ?', [location.Id]);

            // Delete image files from the server
            for (const image of images) {
              const imagePath = path.join(__dirname, image.Cale_Imagine);
              fs.unlink(imagePath, (err) => {
                if (err) {
                  console.error('Error deleting image file:', err);
                }
              });
            }

            // Delete image records from the database
            await db.promise().query('DELETE FROM IMAGINI_LOCATIE WHERE Id_Locatie = ?', [location.Id]);
            await db.promise().query('DELETE FROM CATEGORII_LOCATIE WHERE Id_Locatie = ?', [location.Id]);
          }

          // Delete reviews
          await db.promise().query('DELETE FROM FACE_O_RECENZIE WHERE Id_Utilizator = ?', [userId]);

          // Delete reports
          await db.promise().query('DELETE FROM RAPORTEAZA_RECENZIE WHERE Id_Utilizator = ?', [userId]);
          await db.promise().query('DELETE FROM RAPORTEAZA_LOCATIE WHERE Id_Utilizator = ?', [userId]);

          // Delete locations
          await db.promise().query('DELETE FROM LOCATIE WHERE Id_Proprietar = ?', [userId]);

          // Delete user's favorite locations
          await db.promise().query('DELETE FROM LOCATII_FAVORITE WHERE Id_Utilizator = ?', [userId]);

          // Delete the user
          await db.promise().query('DELETE FROM UTILIZATOR WHERE Id = ?', [userId]);

          // Commit the transaction
          db.commit((err) => {
            if (err) {
              console.error('Error committing transaction:', err);
              db.rollback(() => {
                db.end();
                return res.status(500).json({ message: 'Error committing transaction' });
              });
            } else {
              db.end();
              res.status(200).json({
                message: 'Account deleted successfully',
                userId: userId,
                reviewIds: reviews.map(review => review.Id),
                locationIds: locations.map(location => location.Id),
                reviewReportIds: reviewReports.map(report => report.Id_Recenzie),
                locationReportIds: locationReports.map(report => report.Id_Locatie)
              });
            }
          });
        } catch (error) {
          console.error('Error during transaction:', error);
          db.rollback(() => {
            db.end();
            res.status(500).json({ message: 'Error during transaction' });
          });
        }
      });
    });
  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({ message: 'Unexpected error occurred' });
  }
});



async function getGeocode(address) {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${process.env.GOOGLE_API_KEY}`;
    try {
        const response = await axios.get(url);
        const data = response.data;
        if (data.status === 'OK' && data.results[0]) {
            const { lat, lng } = data.results[0].geometry.location;
            return { lat, lng };
        } else {
            return { error: 'Address not found' };
        }
    } catch (error) {
        return { error: 'Geocoding error occurred' };
    }
}

//ENDPOINT GOOGLE MAPS

// Endpoint-ul `/geocode` care utilizează funcția `getGeocode`
app.get('/geocode', async (req, res) => {
    const { address } = req.query;
    if (!address) {
        return res.status(400).send({ error: 'Address parameter is required.' });
    }

    const location = await getGeocode(address);

    if (location.error) {
        return res.status(404).send(location); // Trimitem răspuns cu codul 404 și mesajul de eroare
    }
    
    res.send(location);
});

app.post('/route', async (req, res) => {
    const { startLat, startLng, endLat, endLng } = req.body;

    if (!startLat || !startLng || !endLat || !endLng) {
        return res.status(400).send({ error: 'Missing required parameters: startLat, startLng, endLat, endLng' });
    }

    const graphHopperURL = `https://graphhopper.com/api/1/route`;

    try {
        const postData = {
            points: [
                [parseFloat(startLng), parseFloat(startLat)],
                [parseFloat(endLng), parseFloat(endLat)]
            ],
            profile: 'foot',
            point_hints: ['Starting Point', 'Destination Point'],
            snap_preventions: ['motorway', 'ferry', 'tunnel'],
            details: ['road_class', 'surface']
        };
        const response = await axios.post(graphHopperURL, postData, {
            headers: { 'Content-Type': 'application/json' },
            params: { key: process.env.GRAPHHOPPER_API_KEY }
        });

        if (response.data.paths && response.data.paths.length > 0) {
            const path = response.data.paths[0];
            const route = {
                start: { lat: startLat, lng: startLng },
                end: { lat: endLat, lng: endLng },
                path: path.points,
                distance: path.distance,
                time: path.time
            };
            res.json(route);
        } else {
            res.status(404).send('No routes found');
        }
    } catch (error) {
        console.error('Failed to retrieve route:', error.response ? error.response.data : error.message);
        res.status(500).send({ error: 'Failed to retrieve route', details: error.message });
    }
});

// Endpoint pentru verificarea informațiilor unei firme
app.post('/check-location', async (req, res) => {
    const { cui, data } = req.body;
    if (!cui || !data) {
        return res.status(400).send('Lipsește CUI-ul sau data.');
    }

    const apiUrl = 'https://facturacloud.ro/app/index.php?section=apianaf';
    const payload = [{
        cui: cui,
        data: data
    }];

    try {
        const response = await axios.post(apiUrl, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (response.data) {
            res.json(response.data);
        } else {
            res.status(404).send('Informații nu au fost găsite pentru firma specificată.');
        }
    } catch (error) {
        console.error('Eroare la solicitarea API:', error);
        res.status(500).send('Eroare de server intern la solicitarea informațiilor firmei.');
    }
});

// Endpoint pentru a prelua categoriile de locații
app.get('/categories', async (req, res) => {
    let credentials; // Definim variabila în scopul global

    // Verificăm dacă există un token și dacă utilizatorul este admin
    if (req.auth && req.auth.role === 'admin') {
        // Accesăm baza de date cu rolul din token
        credentials = getUserDatabaseCredentials(req.auth.role);
    } else {
        // Accesăm baza de date cu rolul "member"
        credentials = getUserDatabaseCredentials('member');
    }

    try {
        const db = connectToDatabase(credentials);
        const connection = await db.promise();
        await connection.connect();

        const query = 'SELECT * FROM CATEGORIE';
        const [categories] = await connection.query(query);

        // Închide conexiunea după ce ai terminat
        await connection.end();

        res.json(categories);
    } catch (error) {
        console.error('Database connection or query error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Endpoint to submit location data and update user role
app.post('/submit-location', verifyToken, upload.array('images'), async (req, res) => {
    const { Nume, Adresa, Tip, CUI, Produse_Servicii, CodQR, Denumire_Companie } = req.body;
    let { selectedCategories } = req.body;
    const userId = req.auth.id;
    const userRole = req.auth.role;
    const images = req.files; // Array of files uploaded

    // Ensure selectedCategories is an array
    if (typeof selectedCategories === 'string') {
        selectedCategories = selectedCategories.split(',').map(item => item.trim());
    }

    const dbCredentials = getUserDatabaseCredentials(userRole === 'location_owner' ? 'location_owner' : 'admin');
    let db = connectToDatabase(dbCredentials);

    try {
        await db.connect();

        // Check if location with a similar address already exists
        const addressCheckQuery = `SELECT Adresa FROM LOCATIE`;
        const [existingAddresses] = await db.promise().query(addressCheckQuery);
        const addressExists = existingAddresses.some(location => 
            areAddressesSimilar(location.Adresa, Adresa)
        );
        
        if (addressExists) {
            return res.status(400).send({ message: 'Eroare: O locație cu o adresă similară există deja în sistem. Vă rugăm să verificați adresa și să încercați din nou.' });
        }

        // Get geolocation data
        const locationData = await getGeocode(Adresa);
        if (!locationData) {
            return res.status(400).send({ message: 'Eroare: Adresa nu a putut fi geocodificată. Vă rugăm să verificați adresa introdusă și să încercați din nou.' });
        }
        const Latitudine = locationData.lat;
        const Longitudine = locationData.lng;

        // Insert location into the database with geolocation
        const insertLocationQuery = `INSERT INTO LOCATIE (Nume, Adresa, Tip, CUI, Produse_Servicii, CodQR, Denumire_Companie, Id_Proprietar, Latitudine, Longitudine) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const results = await db.promise().query(insertLocationQuery, [Nume, Adresa, Tip, CUI, JSON.stringify(Produse_Servicii), CodQR, Denumire_Companie, userId, Latitudine, Longitudine]);
        const locationId = results[0].insertId;

        // Handle images upload only if images are present
        let imagePaths = [];
        if (images && images.length > 0) {
            imagePaths = images.map(file => ({ path: file.path, id_locatie: locationId }));
            const imageValues = imagePaths.map(img => [img.id_locatie, img.path]);

            const insertImagesQuery = `INSERT INTO IMAGINI_LOCATIE (Id_Locatie, Cale_Imagine) VALUES ?`;
            await db.promise().query(insertImagesQuery, [imageValues]);
        }

        // Handle selected categories
        if (selectedCategories.length > 0) {
            const insertCategoryQuery = `INSERT INTO CATEGORII_LOCATIE (Id_Locatie, Id_Categorie) VALUES ?`;
            const categoryValues = selectedCategories.map(catId => [locationId, parseInt(catId)]);
            await db.promise().query(insertCategoryQuery, [categoryValues]);
        }

        // Check if the user's role is not already admin before updating to location_owner
        if (userRole !== 'admin') {
            const updateUserRoleQuery = `UPDATE UTILIZATOR SET Rol = 'location_owner' WHERE Id = ? AND Rol != 'admin'`;
            await db.promise().query(updateUserRoleQuery, [userId]);
        }

        res.status(200).send({
            message: 'Locație adăugată cu succes, inclusiv coordonatele geografice, categoriile sunt legate, iar rolul utilizatorului a fost actualizat.',
            location: {
                Id: locationId,
                Nume,
                Adresa,
                Tip,
                CUI,
                Produse_Servicii,
                CodQR,
                Denumire_Companie,
                Id_Proprietar: userId,
                Latitudine,
                Longitudine,
                Imagini: imagePaths.map(img => img.path),
                Categorii: selectedCategories
            }
        });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare: Nu s-au putut trimite datele locației.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Ensure the database connection is closed
        }
    }
});

// Endpoint pentru a prelua detalii despre locații, imaginile și categoriile asociate
app.get('/locations', async (req, res) => {
    const credentials = getUserDatabaseCredentials('member'); // Folosim credențialele de membru
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        // Interogare pentru a prelua locații și detalii despre acestea, inclusiv categoriile, recenziile și rapoartele
        const query = `
            SELECT l.Id, l.Nume, l.Adresa, l.Tip, l.CUI, l.CodQR, l.Denumire_Companie, l.Produse_Servicii, l.Id_Proprietar, l.Latitudine, l.Longitudine, 
                GROUP_CONCAT(DISTINCT i.Cale_Imagine SEPARATOR ', ') AS Imagini,
                GROUP_CONCAT(DISTINCT c.Id SEPARATOR ', ') AS Categorii,
                GROUP_CONCAT(DISTINCT r.Id SEPARATOR ', ') AS Recenzii,
                GROUP_CONCAT(DISTINCT rl.Id_Utilizator SEPARATOR ', ') AS ReportedBy
            FROM LOCATIE l
            LEFT JOIN IMAGINI_LOCATIE i ON l.Id = i.Id_Locatie
            LEFT JOIN CATEGORII_LOCATIE cl ON l.Id = cl.Id_Locatie
            LEFT JOIN CATEGORIE c ON cl.Id_Categorie = c.Id
            LEFT JOIN FACE_O_RECENZIE r ON l.Id = r.Id_Locatie
            LEFT JOIN RAPORTEAZA_LOCATIE rl ON l.Id = rl.Id_Locatie
            GROUP BY l.Id;
        `;

        const [locations] = await db.promise().query(query);

        const formattedLocations = locations.map(location => ({
            ...location,
            Imagini: location.Imagini ? location.Imagini.split(', ') : [],
            Categorii: location.Categorii ? location.Categorii.split(', ') : [],
            Recenzii: location.Recenzii ? location.Recenzii.split(', ') : [],
            ReportedBy: location.ReportedBy ? location.ReportedBy.split(', ').map(Number) : []
        }));

        res.json(formattedLocations);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare la preluarea datelor despre locații.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Închide conexiunea la baza de date
        }
    }
});


// Functie pentru normalizarea adreselor
const normalizeAddress = (address) => {
    return address.toLowerCase()
        .replace(/str\./g, 'strada')
        .replace(/nr\.?/g, 'numar')
        .replace(/[.,]/g, '') // Elimina punctuatia
        .replace(/\s+/g, ' ') // Elimina spatii multiple
        .trim();
};

// Functie pentru compararea adreselor
const areAddressesSimilar = (address1, address2) => {
    const normalizedAddress1 = normalizeAddress(address1);
    const normalizedAddress2 = normalizeAddress(address2);
    const similarity = stringSimilarity.compareTwoStrings(normalizedAddress1, normalizedAddress2);
    //console.log(similarity);
    return similarity >= 0.73; // Pragul de similaritate poate fi ajustat
};


app.post('/update-location', verifyToken, upload.array('newImages'), async (req, res) => {
    const { locationData } = req.body;
    const newImages = req.files; // Noile imagini încărcate
    const userId = req.auth.id;

    // Parse locationData JSON
    const location = JSON.parse(locationData);
    const { Id, Nume, Adresa, Tip, Produse_Servicii, Categorii, Imagini } = location;

    if (!Id) {
        return res.status(400).send({ message: 'Lipsesc date necesare: Id-ul locației este obligatoriu.' });
    }

    const dbCredentials = getUserDatabaseCredentials('location_owner');
    let db = connectToDatabase(dbCredentials);

    try {
        await db.connect();

        const [existingLocation] = await db.promise().query('SELECT * FROM LOCATIE WHERE Id = ?', [Id]);
        if (existingLocation.length === 0) {
            return res.status(404).send({ message: 'Locația nu a fost găsită.' });
        }

        const location = existingLocation[0];

        if (location.Id_Proprietar !== userId) {
            return res.status(403).send({ message: 'Acces interzis: Nu aveți permisiunea de a modifica această locație.' });
        }

        const fieldsToUpdate = [];
        const values = [];

        // Check for duplicate addresses
        if (Adresa && Adresa !== location.Adresa) {
            const [allLocations] = await db.promise().query('SELECT Adresa FROM LOCATIE WHERE Id != ?', [Id]);
            const isDuplicate = allLocations.some(loc => areAddressesSimilar(loc.Adresa, Adresa));

            if (isDuplicate) {
                return res.status(409).send({ message: 'Există deja o locație cu această adresă.' });
            }

            const locationData = await getGeocode(Adresa);
            if (locationData) {
                fieldsToUpdate.push('Latitudine = ?', 'Longitudine = ?');
                values.push(locationData.lat, locationData.lng);
            }

            fieldsToUpdate.push('Adresa = ?');
            values.push(Adresa);
        }

        if (Nume && Nume !== location.Nume) {
            fieldsToUpdate.push('Nume = ?');
            values.push(Nume);
        }
        if (Tip && Tip !== location.Tip) {
            fieldsToUpdate.push('Tip = ?');
            values.push(Tip);
        }
        if (Produse_Servicii && JSON.stringify(Produse_Servicii) !== location.Produse_Servicii) {
            const produseServiciiString = typeof Produse_Servicii === 'string' ? Produse_Servicii : JSON.stringify(Produse_Servicii);
            fieldsToUpdate.push('Produse_Servicii = ?');
            values.push(JSON.stringify(produseServiciiString));
        }

        if (fieldsToUpdate.length > 0) {
            values.push(Id);
            const updateQuery = `UPDATE LOCATIE SET ${fieldsToUpdate.join(', ')} WHERE Id = ?`;
            await db.promise().query(updateQuery, values);
        }

        if (Categorii && Categorii.length > 0) {
            await db.promise().query('DELETE FROM CATEGORII_LOCATIE WHERE Id_Locatie = ?', [Id]);
            const insertCategoryQuery = `INSERT INTO CATEGORII_LOCATIE (Id_Locatie, Id_Categorie) VALUES ?`;
            const categoryValues = Categorii.map(catId => [Id, parseInt(catId)]);
            await db.promise().query(insertCategoryQuery, [categoryValues]);
        }

        const [existingImages] = await db.promise().query('SELECT Cale_Imagine FROM IMAGINI_LOCATIE WHERE Id_Locatie = ?', [Id]);
        const existingImagePaths = existingImages.map(img => img.Cale_Imagine);

        const normalizedNewImages = Imagini.map(img => img.replace('https://localhost:8080/', ''));

        const imagesToDelete = existingImagePaths.filter(img => !normalizedNewImages.includes(img));

        if (imagesToDelete.length > 0) {
            await db.promise().query('DELETE FROM IMAGINI_LOCATIE WHERE Id_Locatie = ? AND Cale_Imagine IN (?)', [Id, imagesToDelete]);

            imagesToDelete.forEach(imgPath => {
                const fullPath = path.join(__dirname, imgPath);
                fs.unlink(fullPath, err => {
                    if (err) console.error(`Eroare la ștergerea imaginii ${fullPath}:`, err);
                });
            });
        }

        if (newImages && newImages.length > 0) {
            const newImagePaths = newImages.map(file => [Id, `uploads/${file.filename}`]);

            const insertNewImagesQuery = `INSERT INTO IMAGINI_LOCATIE (Id_Locatie, Cale_Imagine) VALUES ?`;
            await db.promise().query(insertNewImagesQuery, [newImagePaths]);
        }

        const [updatedImages] = await db.promise().query('SELECT Cale_Imagine FROM IMAGINI_LOCATIE WHERE Id_Locatie = ?', [Id]);
        const updatedImagePaths = updatedImages.map(img => img.Cale_Imagine);

        // Generate new QR code if location name or address is updated
        let qrCodeDataUrl = null;
        if (Nume || Adresa) {
            qrCodeDataUrl = await generateQRCode(Nume || location.Nume, Adresa || location.Adresa);
            await db.promise().query('UPDATE LOCATIE SET CodQR = ? WHERE Id = ?', [qrCodeDataUrl, Id]);
        }

        res.status(200).send({ 
            message: 'Locația a fost actualizată cu succes.', 
            updatedImages: updatedImagePaths,
            qrCodeUrl: qrCodeDataUrl // Include QR code URL in the response
        });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare: Nu s-au putut actualiza datele locației.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Ensure the database connection is closed
        }
    }
});
app.post('/report-location', verifyToken, async (req, res) => {
    const { locationId, reason } = req.body;
    const userId = req.auth.id;
    const currentDate = new Date();

    if (!locationId || !reason) {
        return res.status(400).send({ message: 'Lipsesc date necesare pentru raportare.' });
    }

    const credentials = getUserDatabaseCredentials('member');
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        const insertReportQuery = `
            INSERT INTO RAPORTEAZA_LOCATIE (Id_Utilizator, Id_Locatie, Motiv, Data)
            VALUES (?, ?, ?, ?)
        `;
        await db.promise().execute(insertReportQuery, [userId, locationId, reason, currentDate]);

        res.status(201).send({ message: 'Locația a fost raportată cu succes!' });
    } catch (error) {
        console.error('Error reporting location:', error);
        res.status(500).send({ message: 'Eroare la raportarea locației.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Închide conexiunea la baza de date
        }
    }
});

app.post('/delete_location', verifyToken, async (req, res) => {
    const { locationId } = req.body;
    const userId = req.auth.id;
    let userRole = req.auth.role;

    const adminCredentials = getUserDatabaseCredentials('admin');
    const adminDb = connectToDatabase(adminCredentials);

    try {
        await adminDb.connect();

        // Verificăm proprietarul locației și preluăm ID-ul proprietarului
        const checkQuery = `
            SELECT Id_Proprietar
            FROM LOCATIE
            WHERE Id = ?
        `;
        const [results] = await adminDb.promise().query(checkQuery, [locationId]);
        const location = results[0];

        if (!location) {
            await adminDb.end();
            return res.status(404).send({ message: 'Locația nu a fost găsită.' });
        }

        const ownerId = location.Id_Proprietar;

        // Dacă utilizatorul nu este admin și nu este proprietarul locației, interzicem accesul
        if (userRole !== 'admin' && ownerId !== userId) {
            await adminDb.end();
            return res.status(403).send({ message: 'Acces interzis: Nu aveți permisiunea de a șterge această locație.' });
        }

        // Preluăm rolul proprietarului din tabela UTILIZATOR
        const ownerRoleQuery = `
            SELECT Rol
            FROM UTILIZATOR
            WHERE Id = ?
        `;
        const [ownerRoleResults] = await adminDb.promise().query(ownerRoleQuery, [ownerId]);
        const ownerRole = ownerRoleResults[0]?.Rol;

        // Ștergem locația și legăturile asociate acesteia
        const selectImagesQuery = `SELECT Cale_Imagine FROM IMAGINI_LOCATIE WHERE Id_Locatie = ?`;
        const [imageResults] = await adminDb.promise().query(selectImagesQuery, [locationId]);

        const deleteQueries = [
            `DELETE FROM RAPORTEAZA_RECENZIE WHERE Id_Recenzie IN (SELECT Id FROM FACE_O_RECENZIE WHERE Id_Locatie = ?)`,
            `DELETE FROM IMAGINI_LOCATIE WHERE Id_Locatie = ?`,
            `DELETE FROM FACE_O_RECENZIE WHERE Id_Locatie = ?`,
            `DELETE FROM LOCATII_FAVORITE WHERE Id_Locatie = ?`,
            `DELETE FROM RAPORTEAZA_LOCATIE WHERE Id_Locatie = ?`,
            `DELETE FROM CATEGORII_LOCATIE WHERE Id_Locatie = ?`
        ];

        for (const query of deleteQueries) {
            await adminDb.promise().query(query, [locationId]);
        }

        const deleteLocationQuery = `DELETE FROM LOCATIE WHERE Id = ?`;
        await adminDb.promise().query(deleteLocationQuery, [locationId]);

        for (const image of imageResults) {
            const imagePath = path.join(__dirname, image.Cale_Imagine);
            fs.unlink(imagePath, (err) => {
                if (err) {
                    console.error(`Eroare la ștergerea imaginii ${imagePath}:`, err);
                }
            });
        }

        // Verificăm dacă utilizatorul mai este proprietarul vreunei alte locații
        const checkOtherLocationsQuery = `SELECT COUNT(*) AS count FROM LOCATIE WHERE Id_Proprietar = ?`;
        const [otherLocationResults] = await adminDb.promise().query(checkOtherLocationsQuery, [ownerId]);

        if (otherLocationResults[0].count === 0 && ownerRole !== 'admin') {
            const updateUserRoleQuery = `UPDATE UTILIZATOR SET Rol = 'member' WHERE Id = ?`;
            await adminDb.promise().query(updateUserRoleQuery, [ownerId]);
        }

        await adminDb.end();

        res.status(200).send({ message: 'Locația a fost ștearsă cu succes.' });
    } catch (error) {
        console.error('Error deleting location:', error);
        if (adminDb.connection) await adminDb.end();
        res.status(500).send({ message: 'Eroare la ștergerea locației.', error });
    }
});
app.post('/recommendations', verifyToken, async (req, res) => {
    const userId = req.auth.id;
    const { latitude, longitude } = req.body;

    if (!latitude || !longitude) {
        return res.status(400).send({ message: 'Latitude and longitude are required.' });
    }

    const proximityThreshold = 1000000; // Define proximity in meters

    const credentials = getUserDatabaseCredentials('member');
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        // Query to get locations that the user has either reviewed, marked as favorite, or are within proximity
        const locationsQuery = `
            SELECT l.Id, l.Nume, l.Adresa, l.Tip, l.CUI, l.CodQR, l.Denumire_Companie, l.Produse_Servicii,
                l.Latitudine, l.Longitudine,
                IF(f.Id_Locatie IS NOT NULL, 'da', 'nu') AS Favorite,
                GROUP_CONCAT(c.Denumire SEPARATOR ',') AS Categorii
            FROM LOCATIE l
            LEFT JOIN LOCATII_FAVORITE f ON l.Id = f.Id_Locatie AND f.Id_Utilizator = ?
            LEFT JOIN FACE_O_RECENZIE r ON l.Id = r.Id_Locatie AND r.Id_Utilizator = ?
            LEFT JOIN CATEGORII_LOCATIE cl ON l.Id = cl.Id_Locatie
            LEFT JOIN CATEGORIE c ON cl.Id_Categorie = c.Id
            WHERE f.Id_Locatie IS NOT NULL OR r.Id_Locatie IS NOT NULL OR 
                  (6371 * ACOS(COS(RADIANS(?)) * COS(RADIANS(l.Latitudine)) * COS(RADIANS(l.Longitudine) - RADIANS(?)) + SIN(RADIANS(?)) * SIN(RADIANS(l.Latitudine)))) <= ?
            GROUP BY l.Id
        `;
        const [locations] = await db.promise().query(locationsQuery, [userId, userId, latitude, longitude, latitude, proximityThreshold / 1000]);

        if (locations.length === 0) {
            return res.status(404).send({ message: 'Nu există date pentru a genera recomandări.' });
        }

        const reviewsQuery = `
            SELECT Id_Locatie, Id_Utilizator, Scor, Data
            FROM FACE_O_RECENZIE
        `;
        const [reviews] = await db.promise().query(reviewsQuery);

        const formattedLocations = locations.map(location => {
            const distance = calculateDistance(latitude, longitude, location.Latitudine, location.Longitudine);
            const proximity = distance <= proximityThreshold ? 'yes' : 'no';
            return {
                Id: location.Id,
                Categorii: location.Categorii ? location.Categorii.split(',') : [],
                ProduseServicii: JSON.parse(location.Produse_Servicii),
                Recenzii: reviews.filter(review => review.Id_Locatie === location.Id).map(review => ({
                    idU: review.Id_Utilizator,
                    scor: review.Scor,
                    data: review.Data.toISOString().split('T')[0]
                })),
                "Reviews utilizator": reviews.filter(review => review.Id_Utilizator === userId && review.Id_Locatie === location.Id).map(review => ({
                    scor: review.Scor,
                    data: review.Data.toISOString().split('T')[0]
                })),
                Favorite: location.Favorite,
                proximity: proximity
            };
        });

        const input_data = {
            user_id: userId,
            threshold: 0.8,
            locations: formattedLocations
        };

        const inputFilePath = path.join(__dirname, 'input_data.json');
        fs.writeFileSync(inputFilePath, JSON.stringify(input_data, null, 2));

        const pythonScript = path.join(__dirname, 'recommandations', 'venv', 'Scripts', 'python.exe');
        const scriptPath = path.join(__dirname, 'recommandations', 'generate_recommendations.py');

        exec(`"${pythonScript}" "${scriptPath}"`, (error, stdout, stderr) => {
            if (error) {
                console.error('Error executing script:', error);
                return res.status(500).json({ error: 'Error generating recommendations', details: error.message });
            }
            if (stderr) {
                console.error('Script stderr:', stderr);
                return res.status(500).json({ error: 'Error generating recommendations', details: stderr });
            }

            const outputFilePath = path.join(__dirname, 'output_data.json');

            const recommendations = JSON.parse(fs.readFileSync(outputFilePath, 'utf-8'));

            res.json({ recommendations });
        });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare la preluarea datelor despre locații.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Ensure the database connection is closed
        }
    }
});





app.get('/reviews', async (req, res) => {
    const credentials = getUserDatabaseCredentials('member'); // Folosim credențialele de membru
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        const query = `
            SELECT r.Id, r.Id_Utilizator, r.Id_Locatie, r.Text, r.Scor, r.Data, r.Ora,
                   u.Nume AS Nume_Utilizator,
                   GROUP_CONCAT(rr.Id_Utilizator) AS ReportedBy
            FROM FACE_O_RECENZIE r
            JOIN UTILIZATOR u ON r.Id_Utilizator = u.Id
            LEFT JOIN RAPORTEAZA_RECENZIE rr ON r.Id = rr.Id_Recenzie
            GROUP BY r.Id, r.Id_Utilizator, r.Id_Locatie, r.Text, r.Scor, r.Data, r.Ora, u.Nume
        `;

        const [reviews] = await db.promise().query(query);

        const formattedReviews = reviews.map(review => ({
            ...review,
            Data: review.Data ? review.Data.toISOString().split('T')[0] : null,
            Ora: review.Ora ? review.Ora.split(':').slice(0, 2).join(':') : null,
            ReportedBy: review.ReportedBy ? review.ReportedBy.split(',').map(Number) : []
        }));

        res.json(formattedReviews);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare la preluarea recenziilor.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Închide conexiunea la baza de date
        }
    }
});

const getFormattedDateTime = () => {
    const data = new Date();
    const options = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Europe/Bucharest' };
    const formattedDate = new Intl.DateTimeFormat('sv-SE', options).format(data);

    const [date, time] = formattedDate.replace(',', '').split(' ');
    return { date, time };
};
app.post('/post-review', verifyToken, async (req, res) => {
    const { idLocatie, text, scor } = req.body;
    const idUtilizator = req.auth.id;
    const userRole = req.auth.Rol;

    const { date: formattedDate, time: formattedTime } = getFormattedDateTime();

    if (!idLocatie || !text || scor === undefined) {
        return res.status(400).send({ message: "Lipsesc date necesare pentru postarea recenziei." });
    }

    try {
        const dbCredentials = getUserDatabaseCredentials(userRole);
        const db = connectToDatabase(dbCredentials);
        await db.connect();
        const checkOwnerQuery = `
            SELECT Id_Proprietar FROM LOCATIE WHERE Id = ?
        `;
        const [owner] = await db.promise().query(checkOwnerQuery, [idLocatie]);

        if (owner[0].Id_Proprietar === idUtilizator) {
            db.end();
            return res.status(403).send({ message: "Proprietarii de locații nu pot lăsa recenzii la propria locație." });
        }

        const checkReviewQuery = `
            SELECT Data, Ora FROM FACE_O_RECENZIE 
            WHERE Id_Utilizator = ? AND Id_Locatie = ? AND Data = ?
            ORDER BY Data DESC, Ora DESC
            LIMIT 1
        `;
        const [lastReview] = await db.promise().query(checkReviewQuery, [idUtilizator, idLocatie, formattedDate]);

        if (lastReview.length > 0) {
            const lastReviewDateStr = `${lastReview[0].Data.toISOString().split('T')[0]}T${lastReview[0].Ora}Z`;
            const lastReviewDate = new Date(lastReviewDateStr);
            const timeDifference = (lastReviewDate - new Date()) / (1000 * 60 * 60); // Diferența în ore

            if (timeDifference < 5) {
                db.end();
                return res.status(403).send({ message: "Recenzia nu a putut fi postată din cauza restricției de timp de 5 ore." });
            }
        }

        const insertQuery = `
            INSERT INTO FACE_O_RECENZIE (Id_Utilizator, Id_Locatie, Text, Scor, Data, Ora)
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        const [result] = await db.promise().execute(insertQuery, [
            idUtilizator, idLocatie, text, scor, formattedDate, formattedTime
        ]);

        const [userResult] = await db.promise().query('SELECT Nume FROM UTILIZATOR WHERE Id = ?', [idUtilizator]);

        const newReview = {
            Id: result.insertId,
            Id_Utilizator: idUtilizator,
            Id_Locatie: idLocatie,
            Text: text,
            Scor: scor,
            Data: formattedDate,
            Ora: formattedTime,
            Nume_Utilizator: userResult[0].Nume // Adaugă numele utilizatorului
        };

        db.end();
        res.status(201).send({ message: "Recenzie postată cu succes!", review: newReview });
    } catch (error) {
        console.error('Error posting review:', error);
        res.status(500).send({ message: "Eroare la postarea recenziei.", error: error.message });
    }
});

// Endpoint pentru raportarea unei recenzii
app.post('/report-review', verifyToken, async (req, res) => {
    const { reviewId, reason } = req.body;
    const userId = req.auth.id;
    const currentDate = new Date();

    if (!reviewId || !reason) {
        return res.status(400).send({ message: 'Lipsesc date necesare pentru raportare.' });
    }

    const credentials = getUserDatabaseCredentials('member');
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        const insertReportQuery = `
            INSERT INTO RAPORTEAZA_RECENZIE (Id_Utilizator, Id_Recenzie, Motiv, Data)
            VALUES (?, ?, ?, ?)
        `;
        await db.promise().execute(insertReportQuery, [userId, reviewId, reason, currentDate]);

        res.status(201).send({ message: 'Recenzia a fost raportată cu succes!' });
    } catch (error) {
        console.error('Error reporting review:', error);
        res.status(500).send({ message: 'Eroare la raportarea recenziei.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Ensure the database connection is closed
        }
    }
});

app.post('/delete_review', verifyToken, async (req, res) => {
    const { reviewId } = req.body;
    const userRole = req.auth.role;

    if (userRole !== 'admin') {
        return res.status(403).send({ message: 'Acces interzis: Doar adminii pot șterge recenzii.' });
    }

    const credentials = getUserDatabaseCredentials(userRole);
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        // Șterge toate raportările recenziei
        const deleteReportsQuery = `
            DELETE FROM RAPORTEAZA_RECENZIE
            WHERE Id_Recenzie = ?
        `;
        await db.promise().query(deleteReportsQuery, [reviewId]);

        // Șterge recenzia
        const deleteReviewQuery = `
            DELETE FROM FACE_O_RECENZIE
            WHERE Id = ?
        `;
        await db.promise().query(deleteReviewQuery, [reviewId]);

        db.end();
        res.status(200).send({ message: 'Recenzia și raportările asociate au fost șterse cu succes.' });
    } catch (error) {
        console.error('Error deleting review and its reports:', error);
        res.status(500).send({ message: 'Eroare la ștergerea recenziei și a raportărilor asociate.', error });
    }
});


app.post('/add-favorite', verifyToken, async (req, res) => {
    const { locationId } = req.body;
    const userId = req.auth.id;
    const userRole = req.auth.role;
    if (!locationId) {
        return res.status(400).send({ message: 'Id-ul locației este necesar.' });
    }

    const credentials = getUserDatabaseCredentials(userRole);
    const db = connectToDatabase(credentials);

    try {
        await db.connect();

        const query = `
            INSERT INTO LOCATII_FAVORITE (Id_Utilizator, Id_Locatie)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE Id_Utilizator=Id_Utilizator, Id_Locatie=Id_Locatie;
        `;

        await db.promise().query(query, [userId, locationId]);

        res.status(200).send({ message: 'Locația a fost adăugată la favorite.' });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare la adăugarea locației la favorite.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Închide conexiunea la baza de date
        }
    }
});


// Endpoint pentru ștergerea unei locații din lista de favorite
app.delete('/remove-favorite', verifyToken, (req, res) => {
    const { locationId } = req.body;
    const userId = req.auth.id;

    const credentials = getUserDatabaseCredentials('member'); // presupunem că toți sunt 'member'
    const db = connectToDatabase(credentials);

    db.connect(err => {
        if (err) {
            console.error('Error connecting to the database:', err);
            return res.status(500).send('Database connection error');
        }

        db.query('DELETE FROM LOCATII_FAVORITE WHERE Id_Utilizator = ? AND Id_Locatie = ?', [userId, locationId], (error, results) => {
            db.end();
            if (error) {
                console.error('Error deleting favorite location:', error);
                return res.status(500).send('Error accessing database');
            }

            if (results.affectedRows === 0) {
                return res.status(404).send('Favorite location not found');
            }

            res.send({ message: 'Favorite location removed successfully' });
        });
    });
});


app.get('/get-reports-locations', async (req, res) => {
    const adminCredentials = getUserDatabaseCredentials('member');
    const adminDb = connectToDatabase(adminCredentials);

    try {
        await adminDb.connect();

        const query = `
            SELECT 
                RL.Id_Utilizator, 
                U.Nume AS ReporterName,
                RL.Id_Locatie, 
                L.Nume AS LocationName, 
                RL.Motiv, 
                RL.Data
            FROM 
                RAPORTEAZA_LOCATIE RL
            JOIN 
                UTILIZATOR U ON RL.Id_Utilizator = U.Id
            JOIN 
                LOCATIE L ON RL.Id_Locatie = L.Id
        `;

        const [results] = await adminDb.promise().query(query);
        await adminDb.end();

        res.status(200).json(results);
    } catch (error) {
        console.error('Error fetching location reports:', error);
        if (adminDb.connection) await adminDb.end();
        res.status(500).json({ message: 'Eroare la preluarea rapoartelor de locații.', error });
    }
});

app.get('/get-reports-reviews', async (req, res) => {
    const adminCredentials = getUserDatabaseCredentials('member');
    const adminDb = connectToDatabase(adminCredentials);

    try {
        await adminDb.connect();

        const query = `
            SELECT 
                RR.Id_Utilizator, 
                U.Nume AS ReporterName,
                RR.Id_Recenzie, 
                R.Text AS ReviewText, 
                RR.Motiv, 
                RR.Data,
                L.Id AS LocationId,
                L.Nume AS LocationName
            FROM 
                RAPORTEAZA_RECENZIE RR
            JOIN 
                UTILIZATOR U ON RR.Id_Utilizator = U.Id
            JOIN 
                FACE_O_RECENZIE R ON RR.Id_Recenzie = R.Id
            JOIN 
                LOCATIE L ON R.Id_Locatie = L.Id
        `;

        const [results] = await adminDb.promise().query(query);
        await adminDb.end();
        res.status(200).json(results);
    } catch (error) {
        console.error('Error fetching review reports:', error);
        if (adminDb.connection) await adminDb.end();
        res.status(500).json({ message: 'Eroare la preluarea rapoartelor de recenzii.', error });
    }
});

app.delete('/delete-report-location', verifyToken, async (req, res) => {
    const { userId, locationId } = req.body;

    const adminCredentials = getUserDatabaseCredentials('admin');
    const adminDb = connectToDatabase(adminCredentials);

    try {
        await adminDb.connect();

        const deleteQuery = `
            DELETE FROM RAPORTEAZA_LOCATIE 
            WHERE Id_Utilizator = ? AND Id_Locatie = ?
        `;
        const [result] = await adminDb.promise().query(deleteQuery, [userId, locationId]);

        await adminDb.end();

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Raportul pentru locație a fost șters cu succes.' });
        } else {
            res.status(404).json({ message: 'Raportul pentru locație nu a fost găsit.' });
        }
    } catch (error) {
        console.error('Error deleting location report:', error);
        if (adminDb.connection) await adminDb.end();
        res.status(500).json({ message: 'Eroare la ștergerea raportului pentru locație.', error });
    }
});

app.delete('/delete-report-review', verifyToken, async (req, res) => {
    const { userId, reviewId } = req.body;

    const adminCredentials = getUserDatabaseCredentials('admin');
    const adminDb = connectToDatabase(adminCredentials);

    try {
        await adminDb.connect();

        const deleteQuery = `
            DELETE FROM RAPORTEAZA_RECENZIE 
            WHERE Id_Utilizator = ? AND Id_Recenzie = ?
        `;
        const [result] = await adminDb.promise().query(deleteQuery, [userId, reviewId]);

        await adminDb.end();

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Raportul pentru recenzie a fost șters cu succes.' });
        } else {
            res.status(404).json({ message: 'Raportul pentru recenzie nu a fost găsit.' });
        }
    } catch (error) {
        console.error('Error deleting review report:', error);
        if (adminDb.connection) await adminDb.end();
        res.status(500).json({ message: 'Eroare la ștergerea raportului pentru recenzie.', error });
    }
});


app.post('/update-produse-servicii', async (req, res) => {
    const locationId = 60;
    const produseServicii = [
        "Filme 2D", 
        "Filme 3D", 
        "Filme de Artă", 
        "Piese de Teatru pentru Copii", 
        "Spectacole de Teatru", 
        "Stand-up Comedy", 
        "Lansări de Carte", 
        "Workshop-uri de Actorie", 
        "Workshop-uri de Filmare și Editare Video", 
        "Cafenea", 
        "Bar cu Băuturi Răcoritoare și Gustări"
    ];
    
    const produseServiciiString = JSON.stringify(produseServicii);

    const dbCredentials = getUserDatabaseCredentials('admin'); // folosim credențialele de admin
    const db = connectToDatabase(dbCredentials);

    try {
        await db.connect();

        const updateQuery = `
            UPDATE LOCATIE
            SET Produse_Servicii = ?
            WHERE Id = ?
        `;
        await db.promise().query(updateQuery, [JSON.stringify(produseServiciiString), locationId]);

        res.status(200).send({ message: 'Produse_Servicii actualizat cu succes.' });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare: Nu s-a putut actualiza Produse_Servicii.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Asigură-te că închizi conexiunea la baza de date
        }
    }
});

app.get('/statistics', async (req, res) => {
    const credentials = getUserDatabaseCredentials('admin');
    const db = connectToDatabase(credentials);

    try {
        await db.connect();
        // Setează limita pentru GROUP_CONCAT
        await db.promise().query('SET SESSION group_concat_max_len = 1000000');
const queries = {
    totalUsers: 'SELECT COUNT(*) AS count FROM UTILIZATOR',
    totalLocations: 'SELECT COUNT(*) AS count FROM LOCATIE',
    totalReviews: 'SELECT COUNT(*) AS count FROM FACE_O_RECENZIE',
    reviewsPerUser: `SELECT u.Nume AS userName, COUNT(*) AS count, AVG(r.Scor) AS avgScore, GROUP_CONCAT(r.Data) AS Dates
                     FROM FACE_O_RECENZIE r 
                     JOIN UTILIZATOR u ON r.Id_Utilizator = u.Id 
                     GROUP BY r.Id_Utilizator, u.Nume`,
    reviewsPerLocation: `SELECT l.Nume AS locationName, COUNT(*) AS count, GROUP_CONCAT(r.Data) AS Dates
                         FROM FACE_O_RECENZIE r 
                         JOIN LOCATIE l ON r.Id_Locatie = l.Id 
                         GROUP BY r.Id_Locatie, l.Nume`,
    reviewsPerLocationTimeFiltered: `SELECT l.Nume AS locationName, DATE_FORMAT(r.Data, '%Y-%m') AS month, COUNT(*) AS count 
                                     FROM FACE_O_RECENZIE r 
                                     JOIN LOCATIE l ON r.Id_Locatie = l.Id 
                                     GROUP BY r.Id_Locatie, l.Nume, month`,
    reviewScoreDistribution: `SELECT Scor, COUNT(*) AS count, GROUP_CONCAT(Data ORDER BY Data) AS Dates
                              FROM FACE_O_RECENZIE
                              GROUP BY Scor
                              ORDER BY Scor`,
    reviewScoreByCategory: `SELECT c.Denumire AS categoryName, r.Scor, COUNT(*) AS count, GROUP_CONCAT(r.Data) AS Dates
                            FROM CATEGORII_LOCATIE cl 
                            JOIN CATEGORIE c ON cl.Id_Categorie = c.Id 
                            JOIN FACE_O_RECENZIE r ON cl.Id_Locatie = r.Id_Locatie 
                            GROUP BY cl.Id_Categorie, c.Denumire, r.Scor`,
    locationsPerCategory: `SELECT c.Denumire AS categoryName, COUNT(*) AS count 
                           FROM CATEGORII_LOCATIE cl 
                           JOIN CATEGORIE c ON cl.Id_Categorie = c.Id 
                           GROUP BY cl.Id_Categorie`,
mostPopularLocations: `SELECT l.Nume AS locationName, COUNT(*) AS count, GROUP_CONCAT(r.Data ORDER BY r.Data) AS Dates
                       FROM FACE_O_RECENZIE r 
                       JOIN LOCATIE l ON r.Id_Locatie = l.Id 
                       GROUP BY r.Id_Locatie 
                       ORDER BY count DESC 
                       LIMIT 5`,
mostPopularCategories: `SELECT c.Denumire AS categoryName, COUNT(*) AS count, GROUP_CONCAT(r.Data ORDER BY r.Data) AS Dates
                        FROM FACE_O_RECENZIE r 
                        JOIN CATEGORII_LOCATIE cl ON r.Id_Locatie = cl.Id_Locatie 
                        JOIN CATEGORIE c ON cl.Id_Categorie = c.Id 
                        GROUP BY cl.Id_Categorie 
                        ORDER BY count DESC 
                        LIMIT 5`}


        const statistics = {};

        for (const [key, query] of Object.entries(queries)) {
            const [result] = await db.promise().query(query);
            statistics[key] = result;
        }

        res.json(statistics);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).send({ message: 'Eroare la preluarea statisticilor.', error });
    } finally {
        if (db && db.end) {
            db.end(); // Ensure database connection is closed
        }
    }
});


const httpsServer = https.createServer(credentials, app);
const port = process.env.PORT || 8080; // You can still use an environment variable to define the port
httpsServer.listen(port, '0.0.0.0', () => {
    console.log(`HTTPS Server running on https://localhost:${port}`);
});
