const Admin = require("../models/Admin")
const { sendEmail } = require("../middleware/helpers")
const SocketMapping = require("../models/SocketMapping")
const Notification = require("../models/Notification")
const jwt = require("jsonwebtoken")
const _ = require("lodash")
const crypto = require("crypto")
const RefreshToken = require("../models/RefereshToken")

exports.signup = async (req, res) => {
  let adminExists
  try {
    adminExists = await Admin.findOne({ email: req.body.email })
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }
  if (adminExists)
    return res.status(403).json({
      error: "Email is taken!"
    })
  const token = jwt.sign({ email: req.body.email }, process.env.JWT_EMAIL_VERIFICATION_KEY, { expiresIn: process.env.EMAIL_TOKEN_EXPIRE_TIME })
  // req.body.emailVerifyLink = token
  let admin = new Admin(req.body)

  try {
    await admin.save()
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }
  const mailingData = {
    from: "Ecom",
    to: admin.email,
    subject: "email verification",
    html: `<p>Hi, ${admin.name} . </p></br>
                    <a href="${process.env.ADMIN_CRM_ROUTE}/email-verify?token=${token}">Click me to verify email for your admin account</a>`
  }
  // await sendEmail(mailingData)
  res.status(200).json({
    msg: `Email has been sent to ${req.body.email} to verify your email address.`
  })
}
// verify email link
exports.emailverify = async (req, res) => {
  const { token } = req.query
  let admin
  try {
    admin = await Admin.findOne({ emailVerifyLink: token })
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  if (!admin || (admin && !admin.emailVerifyLink))
    return res.status(401).json({
      error: "Token is invalid!"
    })
  admin.emailVerifyLink = ""
  admin.updated = Date.now()

  try {
    await admin.save()
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  res.status(201).json({ msg: "Successfully signup!" })
}

exports.signin = async (req, res) => {
  const { email, password } = req.body

  let admin
  try {
    admin = await Admin.findByCredentials(email, password)
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  if (!admin) {
    return res.status(404).json({
      error: "Email or password is invalid."
    })
  }
  if (admin.emailVerifyLink) {
    return res.status(401).json({
      error: "Please verify your email address."
    })
  }
  if (admin.isBlocked) {
    return res.status(401).json({
      error: "Your account has been blocked."
    })
  }
  const payload = {
    _id: admin._id,
    name: admin.name,
    email: admin.email,
    role: admin.role
  }
  const accessToken = jwt.sign(payload, process.env.JWT_SIGNIN_KEY, { expiresIn: process.env.SIGNIN_EXPIRE_TIME })
  let refreshToken = {
    refreshToken: jwt.sign(payload, process.env.REFRESH_TOKEN_KEY, { expiresIn: process.env.REFRESH_TOKEN_EXPIRE }),
    userIP: req.ip
  }
  refreshToken = new RefreshToken(refreshToken)

  try {
    await refreshToken.save()
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  return res.json({ accessToken, refreshToken: refreshToken.refreshToken })
}
exports.refreshToken = async (req, res) => {
  try {
    let refreshToken

    try {
      refreshToken = await RefreshToken.findOne({ refreshToken: req.body.refreshToken, userIP: req.ip })
    } catch (err) {
      return res.status(500).json({
        error: "There was some problem on server end, unable to complete request."
      })
    }

    if (!refreshToken) return res.status(401).json({ error: "Invalid refreshToken" })
    let tokenData = jwt.verify(refreshToken.refreshToken, process.env.REFRESH_TOKEN_KEY)
    if (tokenData.role !== "admin" && tokenData.role !== "superadmin") {
      throw "Invalid refresh token"
    }
    const payload = {
      _id: tokenData._id,
      name: tokenData.name,
      email: tokenData.email,
      role: tokenData.role
    }
    const accessToken = jwt.sign(payload, process.env.JWT_SIGNIN_KEY, { expiresIn: process.env.SIGNIN_EXPIRE_TIME })
    refreshToken.refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_KEY, { expiresIn: process.env.REFRESH_TOKEN_EXPIRE })

    try {
      await refreshToken.save()
    } catch (err) {
      return res.status(500).json({
        error: "There was some problem on server end, unable to complete request."
      })
    }

    return res.json({ accessToken, refreshToken: refreshToken.refreshToken })
  } catch (error) {
    return res.status(401).json({ error: "Invalid refresh token " })
  }
}

exports.loadMe = async (req, res) => {
  req.io.once("connection", async socket => {
    console.log(socket.id, "connected")
    const newSocketMapping = new SocketMapping({
      user: req.admin._id,
      socketId: socket.id
    })
    let notificationObjOfAdmin

    try {
      notificationObjOfAdmin = await Notification.findOne({ admin: req.admin._id })
    } catch (err) {
      return res.status(500).json({
        error: "There was some problem on server end, unable to complete request."
      })
    }

    socket.emit("tx", { hello: "world" })
    if (notificationObjOfAdmin) {
      socket.emit("notification", { noOfUnseen: notificationObjOfAdmin.noOfUnseen })
    }

    try {
      await newSocketMapping.save()
    } catch (err) {
      return res.status(500).json({
        error: "There was some problem on server end, unable to complete request."
      })
    }

    socket.on("disconnect", async () => {
      try {
        await SocketMapping.findOneAndRemove({ socketId: socket.id })
      } catch (err) {
        return res.status(500).json({
          error: "There was some problem on server end, unable to complete request."
        })
      }
      // console.log("user disconnected")
    })
  })
  res.json({ admin: req.admin })
}

exports.forgotPassword = async (req, res) => {
  if (!req.body) return res.status(400).json({ error: "No request body" })
  if (!req.body.email) return res.status(400).json({ error: "No Email in request body" })

  const { email } = req.body
  let admin

  try {
    admin = await Admin.findOne({ email })
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  if (!admin)
    return res.status(404).json({
      error: "Admin with that email does not exist!"
    })

  const token = jwt.sign({ _id: admin._id }, process.env.JWT_EMAIL_VERIFICATION_KEY, { expiresIn: process.env.EMAIL_TOKEN_EXPIRE_TIME })
  const mailingData = {
    from: "Ecom",
    to: admin.email,
    subject: "Password reset Link",
    html: `<p>Hi, ${admin.name} . </p></br>
                    <a href="${process.env.ADMIN_CRM_ROUTE}/reset-password?token=${token}">Click me to reset your password</a>`
  }

  try {
    await admin.updateOne({ resetPasswordLink: token })
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  try {
    await sendEmail(mailingData)
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  res.status(200).json({
    msg: `Email has been sent to ${email}. Follow the instructions to reset your password.`
  })
}

exports.resetPassword = async (req, res) => {
  const { resetPasswordLink, newPassword } = req.body

  let admin

  try {
    admin = await Admin.findOne({ resetPasswordLink })
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  // if err or no admin
  if (!admin || (admin && !admin.resetPasswordLink))
    return res.status(404).json({
      error: "Invalid Link!"
    })

  const updatedFields = {
    password: newPassword,
    resetPasswordLink: ""
  }

  admin = _.extend(admin, updatedFields)
  admin.updated = Date.now()

  try {
    await admin.save()
  } catch (err) {
    return res.status(500).json({
      error: "There was some problem on server end, unable to complete request."
    })
  }

  res.json({
    msg: `Great! Now you can login with your new password.`
  })
}

// authentication middleware
exports.auth = async (req, res, next) => {
  const token = req.header("x-auth-token")
  try {
    if (token) {
      const user = parseToken(token)
      if (user._id) {
        const admin = await Admin.findById(user._id).select("-password -salt")
        if (admin) {
          if (!admin.isBlocked) {
            req.admin = admin
            return next()
          }
          throw "Your account has been blocked"
        }
        throw "Invalid Admin"
      }
      throw user.error
    }
    throw "Token not found"
  } catch (error) {
    console.log("******AUTH ERROR******")
    console.log(error)
    res.status(401).json({ error: error })
  }
}
function parseToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SIGNIN_KEY)
  } catch (error) {
    return { error: error.message }
  }
}

// has authorization middleware
exports.hasAuthorization = async (req, res, next) => {
  try {
    const sameAdmin = req.profile && req.admin && req.profile._id.toString() === req.admin._id.toString()
    const superadmin = req.admin && req.admin.role === "superadmin"
    const canAccess = superadmin || sameAdmin
    if (canAccess) {
      return next()
    }
    throw "Admin is not authorized to perform this action"
  } catch (error) {
    res.status(401).json({ error: error })
  }
}
exports.isSuperAdmin = async (req, res, next) => {
  try {
    const isSuperAdmin = req.admin && req.admin.role === "superadmin"
    if (isSuperAdmin) {
      return next()
    }
    throw "Unauthorized Admin"
  } catch (error) {
    res.status(401).json({ error: error })
  }
}
exports.isAdmin = async (req, res, next) => {
  try {
    const isAdmin = req.admin && req.admin.role === "admin"
    if (isAdmin) {
      return next()
    }
    throw "Unauthorized Admin"
  } catch (error) {
    res.status(401).json({ error: error })
  }
}

exports.checkAdminSignin = async (req, res, next) => {
  const token = req.header("x-auth-token")
  if (token) {
    const admin = parseToken(token)
    if (admin.error === "jwt expired") {
      return res.json(admin) //{error:'jwt expired'}
    }

    let foundUser
    try {
      foundUser = await Admin.findById(admin._id).select("name role")
    } catch (err) {
      return res.status(500).json({
        error: "There was some problem on server end, unable to complete request."
      })
    }

    if (foundUser) {
      if (!foundUser.isBlocked) {
        req.authAdmin = foundUser
      }
    }
  }
  next()
}

/***************************************
 *  DEANINFOTECH PVT LTD.
 *
 *  https://www.deaninfotech.com/
 *
 ***************************************/
