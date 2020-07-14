const express = require('express');
const User = require('../models/user');
const router = new express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const auth = require('../middleware/auth');

router.post('/signup', async (req, res) => {
    const user = new User(req.body);
    try {
        const tokens = await user.generateTokens();
        res.status(201).send({ user, tokens });
    } catch (e) {
        console.log(e);
        res.status(400).send(e);
    }
});
// Первый маршрут
router.post('/login', async (req, res) => {
    try {
        const user = await User.findByCredentials(req.body.email, req.body.password);
        const tokens = await user.generateTokens();
        res.send({ user, tokens });
    } catch (e) {
        res.status(400).send(e);
    }
});

// Get token
router.post('/refresh', auth, async (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (refreshToken == null) {
        return res.sendStatus(401);
    }
    const tokenPair = req.user.tokens.find((tokenPair) => tokenPair.accessToken === req.token);
    const isMatch = await bcrypt.compare(refreshToken, tokenPair.refreshTokenHashed);
    if (!isMatch) {
        return res.status(403).send({error: 'Invalid refresh token'});
    }
    req.user.tokens = req.user.tokens.filter((tokenPair) => tokenPair.accessToken !== req.token);
    const tokens = await req.user.generateTokens();
    res.json(tokens);

    /* jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (error, user) => {
        if (error ) {
            return res.sendStatus(403);
        }
        const accessToken = generateAccessToken({ name: user.name });
        res.json({ accessToken: accessToken });
    });

    if (!refreshTokens.includes(refreshToken)) {
        return res.sendStatus(403);
    } */
});

router.post('/deleteRefresh', auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.map((tokenPair) =>
        (tokenPair.accessToken === req.token ? {accessToken: tokenPair.accessToken, refreshTokenHashed: 'null'} : tokenPair));
        await req.user.save();
        res.send(req.user);
    } catch (e) {
        console.log(e);
    } 
});


router.post('/deleteRefreshAll', auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.map((tokenPair) =>
        ({accessToken: tokenPair.accessToken, refreshTokenHashed: 'null'}));
        console.log(req.user);
        await req.user.save();
        res.send(req.user);
    } catch (e) {
        console.log(e);
    } 
});

module.exports = router;

/* (async () => {
const token1 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI1ZjBiY2Y0Mzg4MDc4ODBjOGMyNDRmZWQiLCJpYXQiOjE1OTQ2MzA4Nzh9.cwyo_fAqbH55jOO0vsRxmTEBBHnLIcelhKCpXSBf0Uc' //jwt.sign('1213441afjlksjf;aafljkfjqfdkja;', 'hi');
const token2 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI1ZjBiY2Y0Mzg4MDc4ODBjOGMyNDRmZWQiLCJpYXQiOjE1OTQ2MjA0MTl9.NbLq4Twxd8A5KoSwqqcAyauswP-8qDJresDPqZOKyCk' //jwt.sign('1213441afjlksjf;aafljkfjqfdkja;', 'hi');
const hash1 =  await bcrypt.hash(token1, 8);
const hash2 =  await bcrypt.hash(token2, 8);
const decode1 = jwt.verify(token1, 'access')
const decode2 = jwt.verify(token2, 'access')

console.log(await bcrypt.compare('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI1ZjBiY2Y0Mzg4MDc4ODBjOGMyNDRmZWQiLCJpYXQiOjE1OTQ2MDk0NzV9.M_4g9JZLr4oPBVaYSC7QIZECAgUy7wGzr3Rb3cez1ar', '$2a$08$vNrLelQmZIuraIeqLcVJqOEJRAYJrz12aI6FeywEgUon1gb9CpVTm'));
console.log(token1, token2);
console.log(decode1, decode2);
})() */