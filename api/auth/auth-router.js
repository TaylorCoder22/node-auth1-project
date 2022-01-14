const router = require('express').Router()
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const {checkPasswordLength, checkUsernameExists, checkUsernameFree} = require('./auth-middleware')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, checkUsernameExists, (req, res, next) => {
  const {username, password} = req.body
  const hash = bcrypt.hashSync(password, 10)
  Users.add({username, password: hash})
  .then(saved => {
    res.status(201).json(saved)
  })
  .catch(next)
})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, checkPasswordLength, (req, res, next) => {
  try{
    const verified = bcrypt.compareSync(req.body.password, req.userData.password)
    if(verified){
      req.session.user = req.userData
      res.json(`Welcome back ${req.userData.password}`)
    }else{
      res.status(401).json('Incorrect username or password')
    }
  }catch(err){
    res.status(500).json(`Server error: ${err.message}`)
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res) => {
  if(req.session.user){
    req.session.destroy(err => {
      if(err){
        next(err)
      }else{
        res.status(200).json({message: 'logged out'})
      }
    })
  }else{
    res.status(200).json({message: 'no session'})
  }
})
 
router.use((err, req, res, next) => {
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack,
    customMessage: 'Something went wrong inside the auth router'
  })
})

module.exports = router