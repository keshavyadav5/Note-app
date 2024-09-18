const express = require('express');
const app = express();
require('dotenv').config();
const db = require('./db');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');

app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors({
  origin: 'https://note-app-frontend-seven.vercel.app',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));




const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes')
app.use('/api/auth', authRoutes);
app.use('/api/note',noteRoutes)

app.get('/', (req, res) => {
  res.send('Hello World');
});
app.get('/test', (req, res) => {
  res.json({ message: "API is working!" });
});


app.use((err, req, res, next) => {
  const statusCode = err.status || 500;
  const message = err.message || "Internal server error";
  console.error('Error stack:', err.stack); 
  
  return res.status(statusCode).json({
    success: false,
    statusCode,
    message
  });
});


const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
