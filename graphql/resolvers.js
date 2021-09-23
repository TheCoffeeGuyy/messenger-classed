const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {User} = require('../models')
const {UserInputError, AuthenticationError} = require('apollo-server')
const { Op} = require('sequelize')

const { JWT_SECRET } = require('../config/env.json')

module.exports = {

    //   Query: {
    //     hello: () => 'worlddd',
    //   },
      Query: {
        getUsers: async (_, __, context) => {
            try {
                let user
                if (context.req && context.req.headers.authorization) {
                    const token = context.req.headers.authorization.split('Bearer ')[1]
                    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
                        if (err) {
                            throw new AuthenticationError('Unauthenticated')
                        }
                        user = decodedToken

                    })
                    
                }
                const res = await User.findAll({
                    where: {
                        username: {
                            [Op.ne]: user.username
                        }
                    }
                })
                return res
            } catch (error) {
                console.log(error)
                throw error
            }
        },
        login: async (_, args) => {
            const { username, password} = args
            const errors = {}
            try {
                if (!username.trim()) errors.username = 'Username must not be empty'
                if (!password) errors.password = 'Password must not be empty'

                if (Object.keys(errors).length) {
                    throw new UserInputError('Bad input', {errors})
                }

                const user = await User.findOne({
                    where: {
                        username
                    }
                })    

                if (!username) {
                    errors.username = 'User not found'
                    throw new UserInputError('User not found', {errors})
                }

                const correctPassword = await bcrypt.compare(password, user.password)
                if (!correctPassword) {
                    errors.password = 'Password is incorrect'
                    throw new AuthenticationError('Password is incorrect', {errors}) 
                }

                const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h'})
                return {
                    ...user.toJSON(),
                    createdAt: user.createdAt.toISOString(),
                    token
                }
            } catch (error) {
                console.log(error)
                throw error
            }
        }
      },
      Mutation: {
        register: async (_, args) => {
            let { username, email, password, confirmPassword} = args
            let errors = {}
            try {
                // Validate input data
                if (!username.trim()) errors.username = 'Username must not be empty'
                if (!email.trim()) errors.email = 'Email must not be empty'
                if (!password.trim()) errors.password = 'Password must not be empty'
                if (!confirmPassword.trim()) errors.confirmPassword = 'Confirm Password must not be empty'
                if (password !== confirmPassword) errors.confirmPassword = 'Confirm Password must match'
                // Check if username / email exists
                // const userByUsername = await User.findOne({
                //     where: {
                //         username
                //     }
                // })
                // const userByEmail = await User.findOne({
                //     where: {
                //         email
                //     }
                // })

                // if (userByUsername) errors.username = 'Username is taken'
                // if (userByEmail) errors.email = 'Email is taken'

                if (Object.keys(errors).length) {
                    throw errors
                }
                // Hash Password
                password = await bcrypt.hash(password, 6)
                // Create user
                const user = await User.create({
                    username,
                    email,
                    password
                })
                // Return user
                return user
            } catch (error) {
                console.log(error)
                if (error.name === 'SequelizeUniqueConstraintError') {
                    error.errors.forEach(e => (errors[e.path] = `${e.path} is already taken`))
                } else if (error.name === 'SequelizeValidationError') {
                    error.errors.forEach(e => (errors[e.path] = e.message))
                }
                throw new UserInputError('Bad inputs', {errors})
            }
        }
      }
};