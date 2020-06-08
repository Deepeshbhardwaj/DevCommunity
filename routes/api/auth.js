const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config')
const { check, validationResult } = require('express-validator');


// @route    GET api/auth
// @desc     Test route
// @access   Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user)
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Sevrer Error')
    }
});

module.exports = router;



// @route    GET api/users
// @desc     Register route
// @access   Public

router.post('/',[
    check('email', 'Please include a valid email').isEmail(),
    check(
        'password',
        'Password is Required'
    ).exists()],
    async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()});
    }

    const {email, password} = req.body

    try {

        // See if the user exists

        let user = await User.findOne({email});

        if(!user) {
            return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch) {
            return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
        }

        const payload = {
            user: {
                id: user.id
            }
        }
        
        jwt.sign(payload,config.get('jwtSecret'),{expiresIn: 3600000}, (err,token)=> {
            if(err) throw err;  
            res.json({token})
        });

        
    } catch (error) {
        console.log(err.message);
        res.status(500).send('Server error')
    }



    
});