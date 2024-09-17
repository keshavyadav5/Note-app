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
  origin: 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));



app.use(express.json());


const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes')
app.use('/api/auth', authRoutes);
app.use('/api/note',noteRoutes)

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.use((err, req, res, next) => {
  const statusCode = err.status || 500;
  const message = err.message || "Internal server error";

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