//Step 1 - Task 2: Import necessary packages
const express = require('express');
const app = express();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {body,validationResult} = require('express-validator');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');

//Step 1 - Task 3: Create a Pino logger instance
dotenv.config();
const logger = pino();
//Step 1 - Task 4: Create JWT secret
const JWT_SECRET = process.env.JWT_SECRET;
router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
        const db = await connectToDatabase();
        // Task 2: Access MongoDB collection
         const collection = await db.collection('users');
        //Task 3: Check for existing email
        const existingEmail = await collection.findOne({email: req.body.email});
        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email = req.body.email;
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        }) //Task 4: Save user details in database
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };
        const authtoken = jwt.sign(payload,JWT_SECRET); //Task 5: Create JWT authentication with user._id as payload
        logger.info('User registered successfully');
        res.json({authtoken,email});
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req,res)=>{
    try {
        const db = await connectToDatabase();
        const collection = db.collection('users');
        const theUser = await collection.findOne({email: req.body.email});
        if (theUser) {
            let result = await bcryptjs.compare(req.body.password,theUser.password);
            if (!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({error: 'Wrong password'});
            }
            const userName = theUser.firstName;
            const userEmail = theUser.email;
            const payload = {
                user: {
                    id: theUser._id.toString(),
                },
            };
            const authtoken = jwt.sign(payload,JWT_SECRET);
            res.json({authtoken,userName,userEmail});
        } else {
            logger.error('User not found');
            return res.status(404).json({error: 'User not found'});
        }
    } catch (e) {
        return res.status(500).send('Internal server error');
    }
});

module.exports = router;