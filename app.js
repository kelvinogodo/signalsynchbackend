const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const rateLimit = require('express-rate-limit')
const User = require('./models/user.model')
const Admin = require('./models/admin')
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Token = require('./models/token')
const Trader = require('./models/trader')
const AuditLog = require('./models/auditlog')
const PasswordResetToken = require('./models/passwordResetToken')
dotenv.config()

const app = express()

if (!process.env.JWT_SECRET) {
  throw new Error("Please define the JWT_SECRET environment variable. Refusing to start with no secret configured.");
}

const jwtSecret = process.env.JWT_SECRET;

// CORS: explicit allowlist instead of '*'. Add any additional deployed frontend
// origins (staging, preview URLs) here.
const allowedOrigins = [
  'https://www.signalsynch.com',
  'https://signalsynch.com',
  'http://localhost:3000',
]

app.use(cors({
  origin: function (origin, callback) {
    // Allow non-browser tools / same-origin requests with no Origin header.
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true)
    }
    return callback(new Error('Not allowed by CORS'))
  }
}))
app.use(express.json())

const ATLAS_URI = process.env.ATLAS_URI;

if (!ATLAS_URI) {
  throw new Error("Please define the ATLAS_URI environment variable in Vercel");
}

/* Global cache so we don’t reconnect every time */
let cached = global.mongoose;
if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

const connectDB = async () => {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    cached.promise = mongoose.connect(ATLAS_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }).then((mongoose) => mongoose);
  }

  cached.conn = await cached.promise;
  return cached.conn;
}
connectDB()

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

function requireAuth(req, res, next) {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(401).json({ status: 'error', message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.tokenEmail = decoded.email;
    req.tokenUserId = decoded.id;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ status: 'error', message: 'Token expired' });
    }
    return res.status(401).json({ status: 'error', message: 'Invalid token' });
  }
}

function requireAdminAuth(req, res, next) {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(401).json({ status: 'error', message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ status: 'error', message: 'Admin access required' });
    }
    req.adminEmail = decoded.email;
    req.adminId = decoded.adminId;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ status: 'error', message: 'Token expired' });
    }
    return res.status(401).json({ status: 'error', message: 'Invalid token' });
  }
}

// Lets a scheduled job (e.g. an external cron pinger) trigger /api/cron with a
// shared secret header, OR an admin can trigger it manually with their token.
function requireCronOrAdmin(req, res, next) {
  const cronSecret = process.env.CRON_SECRET;
  const provided = req.headers['x-cron-secret'];
  if (cronSecret && provided === cronSecret) {
    return next();
  }
  return requireAdminAuth(req, res, next);
}

async function logAudit(req, { action, target, success, details, actorEmail }) {
  try {
    await AuditLog.create({
      adminEmail: actorEmail || req.adminEmail || 'unknown',
      action,
      target: target || '',
      ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '',
      success: !!success,
      details: details || {},
    });
  } catch (err) {
    console.error('Failed to write audit log:', err);
  }
}

function isValidAmount(value) {
  const num = Number(value);
  return Number.isFinite(num) && num > 0;
}

// ---------------------------------------------------------------------------
// Rate limiters
// ---------------------------------------------------------------------------

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many login attempts. Please try again later.' },
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many login attempts. Please try again later.' },
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many password reset requests. Please try again later.' },
});

app.post('/api/verify', requireAdminAuth, async (req, res) => {
  const {
    id
  } = req.body
  try {
    const user = await User.findOne({ _id: id, deleted: { $ne: true } })
    if (!user) {
      return res.json({ status: 400, message: 'User not found' })
    }

    if (user.verified) {
      await User.updateOne({ _id: id }, {
        verified: false
      })
      await logAudit(req, { action: 'toggle_pdt_verified', target: id, success: true, details: { newValue: false } })
      res.json({
        status: 200, verified: user
      })
    }
    else {
      await User.updateOne({ _id: id }, {
        verified: true
      })
      await logAudit(req, { action: 'toggle_pdt_verified', target: id, success: true, details: { newValue: true } })
      res.json({
        status: 201, verified: user
      })
    }
  } catch (error) {
    await logAudit(req, { action: 'toggle_pdt_verified', target: id, success: false, details: { error: String(error) } })
    res.json({ status: 400, message: `error ${error}` })
  }
})

app.post('/api/copytrade', requireAuth, async (req, res) => {
  const trader = req.body.trader
  try {
    const email = req.tokenEmail
    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (!user) {
      return res.json({ status: 400, message: 'User not found' })
    }

    const Trader = await User.updateOne
      ({ email: user.email },
        { trader: trader })

    res.json({ status: 200, message: 'trader successfully added', trader: Trader })

  } catch (error) {
    res.json({ status: 400, message: `error ${error}` })
  }
})
app.post('/api/stopcopytrade', requireAuth, async (req, res) => {
  try {
    const email = req.tokenEmail
    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (!user) {
      return res.json({ status: 400, message: 'User not found' })
    }

    await User.updateOne
      ({ email: user.email },
        { trader: '' })

    res.json({ status: 200, message: 'trader successfully removed' })

  } catch (error) {
    res.json({ status: 400, message: `error ${error}` })
  }
})

// register route
app.post(
  '/api/register',
  async (req, res) => {
    const { firstName, lastName, userName, password, email, referralLink, server, phonenumber, deviceName, country } = req.body;
    const now = new Date();

    try {
      // Check if the user already exists
      const existingUser = await User.findOne({ email: email });
      if (existingUser) {
        return res.status(409).json({ status: 'error', message: 'Email or username already exists' });
      }

      // Check for referring user
      const referringUser = await User.findOne({ username: referralLink });
      if (referringUser) {

        // Update referring user's referral info

        await User.updateOne(
          { username: referralLink },
          {
            $push: {
              referred: {
                firstname: firstName,
                lastname: lastName,
                email: email,
                date: now.toLocaleString(),
                refBonus: 15,
              },
            },
            refBonus: referringUser.refBonus + 500,
            totalProfit: referringUser.totalProfit + 15,
            funded: referringUser.funded + 15,
            capital: referringUser.capital + 15
          }
        );
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user
      const newUser = await User.create({
        firstname: firstName,
        lastname: lastName,
        username: userName,
        email,
        phonenumber,
        password: hashedPassword,
        funded: 0,
        investment: [],
        transaction: [],
        withdraw: [],
        rememberme: false,
        referral: crypto.randomBytes(32).toString('hex'),
        refBonus: 0,
        referred: [],
        periodicProfit: 0,
        upline: referralLink || null,
        trades: [],
        server: server || "server1"
      });

      // Generate JWT token
      const token = jwt.sign(
        { id: newUser._id, email: newUser.email },
        jwtSecret,
        { expiresIn: '1h' }
      );
      const user = await User.findOne({ email: email })
      //create verification link
      const VerificationCode = await Token.create({
        userId: user._id, token: token
      })

      const verificationLink = `https://www.signalsynch.com/${user._id}/verify/${token}`

      // Prepare response data
      const response = {
        status: 'ok',
        email: newUser.email,
        name: newUser.firstname,
        token,
        verificationLink: verificationLink,
        adminSubject: 'User Signup Alert',
        message: `A new user with the following details just signed up:\nName: ${firstName} ${lastName}\nEmail: ${email} \nlocation: ${country} \ndevice: ${deviceName}`,
        subject: 'Successful User Referral Alert',
      };

      if (referringUser) {
        response.referringUserEmail = referringUser.email;
        response.referringUserName = referringUser.firstname;
        response.referringUserMessage = `A new user with the name ${firstName} ${lastName} just signed up with your referral link. You will now earn 10% of every deposit this user makes. Keep referring to earn more.`;
      } else {
        response.referringUser = null;
      }

      return res.status(201).json(response);
    } catch (error) {
      console.error('Error during user registration:', error);
      return res.status(500).json({ status: 'error', message: 'Server error. Please try again later.' });
    }
  }
);

app.get('/:id/refer', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.id })
    if (!user) {
      return res.json({ status: 400 })
    }
    res.json({ status: 200, referredUser: req.params.id })
  } catch (error) {
    console.log(error)
    res.json({ status: `internal server error ${error}` })
  }
})


app.get('/api/getData', requireAuth, async (req, res) => {
  try {
    const email = req.tokenEmail;

    // Fetch user data
    const user = await User.findOne({ email, deleted: { $ne: true } });
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // Respond with user details
    res.status(200).json({
      status: 'ok',
      firstname: user.firstname,
      lastname: user.lastname,
      username: user.username,
      email: user.email,
      funded: user.funded,
      invest: user.investment,
      transaction: user.transaction,
      withdraw: user.withdraw,
      refBonus: user.refBonus,
      referred: user.referred,
      referral: user.referral,
      phonenumber: user.phonenumber,
      state: user.state,
      zipcode: user.zipcode,
      address: user.address,
      profilepicture: user.profilepicture,
      country: user.country,
      totalprofit: user.totalprofit,
      totaldeposit: user.totaldeposit,
      totalwithdraw: user.totalwithdraw,
      deposit: user.deposit,
      promo: user.promo,
      periodicProfit: user.periodicProfit,
      trader: user.trader,
      rank: user.rank,
      server: user.server,
      trades: user.trades,
      verified: user.verified
    });
  } catch (error) {
    console.error('Error fetching user data:', error.message);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});


const ALLOWED_USER_UPDATE_FIELDS = [
  'firstname', 'lastname', 'phonenumber', 'state',
  'zipcode', 'address', 'profilepicture', 'country'
];

app.post('/api/updateUserData', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.tokenEmail, deleted: { $ne: true } });

    if (!user) {
      return res.json({ status: 400, message: "User not found" });
    }

    // Only a fixed, explicit whitelist of self-service profile fields can be
    // changed here. Financial/verification/role fields are never accepted
    // from this endpoint.
    let updatedFields = {};
    ALLOWED_USER_UPDATE_FIELDS.forEach((key) => {
      if (req.body[key] !== undefined && req.body[key] !== user[key]) {
        updatedFields[key] = req.body[key];
      }
    });

    if (Object.keys(updatedFields).length > 0) {
      await User.updateOne({ _id: user._id }, { $set: updatedFields });
      return res.json({ status: 200, message: "Profile updated successfully" });
    }

    return res.json({ status: 400, message: "No changes were made" });

  } catch (error) {
    console.error(error);
    return res.json({ status: 500, message: "Internal server error" });
  }
});




app.post('/api/fundwallet', requireAdminAuth, async (req, res) => {
  const email = req.body.email
  const incomingAmount = Number(req.body.amount)
  try {
    if (!isValidAmount(incomingAmount)) {
      await logAudit(req, { action: 'credit_wallet', target: email, success: false, details: { reason: 'invalid amount', amount: req.body.amount } })
      return res.status(400).json({ status: 'error', message: 'Amount must be a positive number' })
    }

    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (!user) {
      await logAudit(req, { action: 'credit_wallet', target: email, success: false, details: { reason: 'user not found' } })
      return res.status(404).json({ status: 'error', message: 'User not found' })
    }

    await User.updateOne(
      { email: email }, {
      $set: {
        funded: incomingAmount + user.funded,
        capital: user.capital + incomingAmount,
        totaldeposit: user.totaldeposit + incomingAmount
      }
    }
    )
    const upline = await User.findOne({ username: user.upline, deleted: { $ne: true } })
    if (upline) {
      await User.updateOne({ username: user.upline }, {
        $set: {
          refBonus: 10 / 100 * incomingAmount,
          totalprofit: upline.totalprofit + (10 / 100 * incomingAmount),
          capital: upline.capital + (10 / 100 * incomingAmount),
          funded: upline.funded + (10 / 100 * incomingAmount),
        }
      })
    }

    await User.updateOne(
      { email: email },
      {
        $push: {
          deposit: {
            date: new Date().toLocaleString(),
            amount: incomingAmount,
            id: crypto.randomBytes(32).toString("hex"),
            balance: incomingAmount + user.funded
          }
        }, transaction: {
          type: 'Deposit',
          amount: incomingAmount,
          date: new Date().toLocaleString(),
          balance: incomingAmount + user.funded,
          id: crypto.randomBytes(32).toString("hex"),
        }
      }
    )

    await logAudit(req, { action: 'credit_wallet', target: email, success: true, details: { amount: incomingAmount } })

    if (upline) {
      res.json({
        status: 'ok',
        funded: incomingAmount,
        name: user.firstname,
        email: user.email,
        message: `your account has been credited with $${incomingAmount} USD. you can proceed to choosing your preferred investment plan to start earning. Thanks.`,
        subject: 'Deposit Successful',
        uplineName: upline.firstname,
        uplineEmail: upline.email,
        uplineSubject: `Earned Referral Commission`,
        uplineMessage: `Congratulations! You just earned $${10 / 100 * incomingAmount} in commission from ${user.firstname} ${user.lastname}'s deposit of $${incomingAmount}.`
      })
    }
    else {
      res.json({
        status: 'ok',
        funded: incomingAmount,
        name: user.firstname,
        email: user.email,
        message: `your account has been credited with $${incomingAmount} USD. you can proceed to choosing your preferred investment plan to start earning. Thanks.`,
        subject: 'Deposit Successful',
        upline: null
      })
    }

  } catch (error) {
    console.log(error)
    await logAudit(req, { action: 'credit_wallet', target: email, success: false, details: { error: String(error) } })
    res.json({ status: 'error' })
  }
})

app.post('/api/debitwallet', requireAdminAuth, async (req, res) => {
  const email = req.body.email
  const incomingAmount = Number(req.body.amount)
  try {
    if (!isValidAmount(incomingAmount)) {
      await logAudit(req, { action: 'debit_wallet', target: email, success: false, details: { reason: 'invalid amount', amount: req.body.amount } })
      return res.status(400).json({ status: 'error', message: 'Amount must be a positive number' })
    }

    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (!user) {
      await logAudit(req, { action: 'debit_wallet', target: email, success: false, details: { reason: 'user not found' } })
      return res.status(404).json({ status: 'error', message: 'User not found' })
    }

    if (incomingAmount <= user.funded) {
      await User.updateOne(
        { email: email }, {
        $set: {
          funded: user.funded - incomingAmount,
          capital: user.capital - incomingAmount,
        }
      }
      )

      await User.updateOne(
        { email: email },
        {
          $push: {
            deposit: {
              date: new Date().toLocaleString(),
              amount: incomingAmount,
              id: crypto.randomBytes(32).toString("hex"),
              balance: user.funded - incomingAmount
            }
          }, transaction: {
            type: 'debit',
            amount: incomingAmount,
            date: new Date().toLocaleString(),
            balance: user.funded - incomingAmount,
            id: crypto.randomBytes(32).toString("hex"),
          }
        }
      )

      await logAudit(req, { action: 'debit_wallet', target: email, success: true, details: { amount: incomingAmount } })

      res.json({
        status: 'ok',
        funded: incomingAmount,
        name: user.firstname,
        email: user.email,
        message: `your account has been debited with $${incomingAmount} USD, Thanks.`,
        subject: 'Debit Alert',
        upline: null
      })
    }
    else {
      await logAudit(req, { action: 'debit_wallet', target: email, success: false, details: { reason: 'insufficient funds', amount: incomingAmount } })
      res.json({
        status: 'error',
        funded: incomingAmount,
        error: 'capital cannot be negative'
      })
    }
  } catch (error) {
    console.log(error)
    await logAudit(req, { action: 'debit_wallet', target: email, success: false, details: { error: String(error) } })
    res.json({ status: 'error' })
  }
})


app.post('/api/admin', adminLoginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body
    const admin = await Admin.findOne({ email })

    if (!admin) {
      await logAudit(req, { action: 'admin_login', actorEmail: email, success: false, details: { reason: 'unknown email' } })
      return res.json({ status: 400 })
    }

    let passwordMatches = false
    let needsRehash = false

    if (typeof admin.password === 'string' && admin.password.startsWith('$2')) {
      passwordMatches = await bcrypt.compare(password, admin.password)
    } else {
      // Legacy plaintext admin account: verify by equality, then silently
      // upgrade to a bcrypt hash on this successful match.
      passwordMatches = password === admin.password
      needsRehash = passwordMatches
    }

    if (!passwordMatches) {
      await logAudit(req, { action: 'admin_login', actorEmail: email, success: false, details: { reason: 'incorrect password' } })
      return res.json({ status: 400 })
    }

    if (needsRehash) {
      admin.password = await bcrypt.hash(password, 10)
      await admin.save()
    }

    const token = jwt.sign(
      { adminId: admin._id, email: admin.email, role: 'admin' },
      jwtSecret,
      { expiresIn: '8h' }
    )

    await logAudit(req, { action: 'admin_login', actorEmail: email, success: true })
    return res.json({ status: 200, token })
  } catch (error) {
    console.error('Error during admin login:', error)
    return res.json({ status: 500 })
  }
})


app.post('/api/deleteUser', requireAdminAuth, async (req, res) => {
  const { email } = req.body
  try {
    await User.updateOne({ email }, { $set: { deleted: true, deletedAt: new Date() } })
    await logAudit(req, { action: 'delete_user', target: email, success: true })
    return res.json({ status: 200 })
  } catch (error) {
    await logAudit(req, { action: 'delete_user', target: email, success: false, details: { error: String(error) } })
    return res.json({ status: 500, msg: `${error}` })
  }
})

app.post('/api/admin/restoreUser', requireAdminAuth, async (req, res) => {
  const { email } = req.body
  try {
    await User.updateOne({ email }, { $set: { deleted: false, deletedAt: null } })
    await logAudit(req, { action: 'restore_user', target: email, success: true })
    return res.json({ status: 200 })
  } catch (error) {
    await logAudit(req, { action: 'restore_user', target: email, success: false, details: { error: String(error) } })
    return res.json({ status: 500, msg: `${error}` })
  }
})

app.post('/api/deleteTrader', requireAdminAuth, async (req, res) => {
  const { id } = req.body
  try {
    await Trader.updateOne({ _id: id }, { $set: { deleted: true, deletedAt: new Date() } })
    await logAudit(req, { action: 'delete_trader', target: id, success: true })
    return res.json({ status: 200 })
  } catch (error) {
    await logAudit(req, { action: 'delete_trader', target: id, success: false, details: { error: String(error) } })
    return res.json({ status: 500, msg: `${error}` })
  }
})

app.post('/api/admin/restoreTrader', requireAdminAuth, async (req, res) => {
  const { id } = req.body
  try {
    await Trader.updateOne({ _id: id }, { $set: { deleted: false, deletedAt: null } })
    await logAudit(req, { action: 'restore_trader', target: id, success: true })
    return res.json({ status: 200 })
  } catch (error) {
    await logAudit(req, { action: 'restore_trader', target: id, success: false, details: { error: String(error) } })
    return res.json({ status: 500, msg: `${error}` })
  }
})

app.post('/api/upgradeUser', requireAdminAuth, async (req, res) => {
  const email = req.body.email
  const incomingAmount = Number(req.body.amount)
  try {
    if (!isValidAmount(incomingAmount)) {
      await logAudit(req, { action: 'upgrade_user', target: email, success: false, details: { reason: 'invalid amount', amount: req.body.amount } })
      return res.status(400).json({ status: 'error', message: 'Amount must be a positive number' })
    }

    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (user) {
      await User.updateOne(
        { email: email }, {
        $set: {
          funded: incomingAmount + user.funded,
          capital: user.capital + incomingAmount,
          totalProfit: user.totalprofit + incomingAmount,
          periodicProfit: user.periodicProfit + incomingAmount
        }
      }
      )
      await logAudit(req, { action: 'upgrade_user', target: email, success: true, details: { amount: incomingAmount } })
      res.json({
        status: 'ok',
        funded: incomingAmount
      })
    } else {
      await logAudit(req, { action: 'upgrade_user', target: email, success: false, details: { reason: 'user not found' } })
      res.status(404).json({ status: 'error', message: 'User not found' })
    }
  }
  catch (error) {
    await logAudit(req, { action: 'upgrade_user', target: email, success: false, details: { error: String(error) } })
    res.json({
      status: 'error',
    })
  }


})


app.post('/api/updateTraderLog', requireAdminAuth, async (req, res) => {
  try {
    const {
      tradeLog
    } = req.body
    const id = tradeLog.id
    const updatedTrader = await Trader.updateOne(
      { _id: id }, {
      $push: {
        tradehistory: tradeLog
      }
    }
    )
    if (tradeLog.tradeType === 'profit') {
      const updatedUsers = await User.updateMany({ trader: id, deleted: { $ne: true } }, {
        $push: {
          trades: tradeLog
        },
        $inc: {
          funded: tradeLog.amount,
          capital: tradeLog.amount,
          totalProfit: tradeLog.amount,
        }
      })
      await logAudit(req, { action: 'update_trader_log', target: id, success: true, details: { tradeType: 'profit', amount: tradeLog.amount } })
      res.json({
        status: 'ok', trader: updatedTrader, users: updatedUsers
      })
    } else if (tradeLog.tradeType === 'loss') {
      const updatedUsers = await User.updateMany({ trader: id, deleted: { $ne: true } }, {
        $push: {
          trades: tradeLog
        },
        $inc: {
          funded: -tradeLog.amount,
          capital: -tradeLog.amount,
          totalProfit: -tradeLog.amount,
        }
      })
      await logAudit(req, { action: 'update_trader_log', target: id, success: true, details: { tradeType: 'loss', amount: tradeLog.amount } })
      res.json({
        status: 'ok', trader: updatedTrader, users: updatedUsers
      })
    }

  }
  catch (error) {
    await logAudit(req, { action: 'update_trader_log', success: false, details: { error: String(error) } })
    res.json({
      status: 'error',
    })
  }
})

app.post('/api/distributeProfit', requireAdminAuth, async (req, res) => {
  try {
    const { distributions, traderId, addToHistory, masterTradeLog } = req.body;

    const results = await Promise.all(distributions.map(async (dist) => {
      try {
        const { email, amount, type, pair } = dist;
        const numericAmount = Number(amount);

        if (!isValidAmount(numericAmount)) {
          return { email, status: 'error', error: 'Invalid amount' };
        }

        // Define trade log for user
        const userTradeLog = {
          pair: pair || (masterTradeLog ? masterTradeLog.pair : 'Unknown'),
          amount: numericAmount,
          tradeType: type, // 'profit' or 'loss'
          date: new Date().toLocaleDateString(),
          id: crypto.randomBytes(16).toString("hex")
        };

        const updateOperation = type === 'profit' ? {
          $push: { trades: userTradeLog },
          $inc: {
            funded: numericAmount,
            capital: numericAmount,
            totalProfit: numericAmount,
          }
        } : { // type === 'loss'
          $push: { trades: userTradeLog },
          $inc: {
            funded: -numericAmount,
            capital: -numericAmount,
            totalProfit: -numericAmount,
          }
        };

        const updatedUser = await User.updateOne({ email: email, deleted: { $ne: true } }, updateOperation);
        return { email, status: 'ok', user: updatedUser };

      } catch (err) {
        console.error(`Error updating user ${dist.email}:`, err);
        return { email: dist.email, status: 'error', error: err.message };
      }
    }));

    // Optionally update trader's master history
    if (addToHistory && masterTradeLog && traderId) {
      await Trader.updateOne(
        { _id: traderId },
        { $push: { tradehistory: masterTradeLog } }
      );
    }

    await logAudit(req, { action: 'distribute_profit', target: traderId || '', success: true, details: { count: distributions.length } })

    res.json({ status: 'ok', results });

  } catch (error) {
    console.error("Global distribution error:", error);
    await logAudit(req, { action: 'distribute_profit', success: false, details: { error: String(error) } })
    res.json({ status: 'error', message: error.message });
  }
})

app.post('/api/withdraw', requireAuth, async (req, res) => {
  try {
    const email = req.tokenEmail
    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (!user) {
      return res.json({ status: 'error', message: 'User not found' })
    }

    const withdrawAmount = Number(req.body.WithdrawAmount)
    if (!isValidAmount(withdrawAmount)) {
      return res.status(400).json({ status: 'error', message: 'Withdraw amount must be a positive number' })
    }

    if (user.funded >= withdrawAmount) {

      await User.updateOne(
        { email: email },
        { $set: { withdrawAmount: withdrawAmount } }
      )
      return res.json({
        status: 'ok',
        withdraw: withdrawAmount,
        email: user.email,
        name: user.firstname,
        message: `We have received your withdrawal order, kindly exercise some patience as our management board approves your withdrawal`,
        subject: 'Withdrawal Order Alert',
        adminMessage: `Hello BOSS! a user with the name ${user.firstname} placed withdrawal of $${withdrawAmount} USD, to be withdrawn into ${req.body.wallet} ${req.body.method} wallet`,
      })
    }

    else {
      res.json({
        status: 400,
        subject: 'Failed Withdrawal Alert',
        email: user.email,
        name: user.firstname,
        withdrawMessage: `We have received your withdrawal order, but you can only withdraw you insufficient amount in your account. Kindly deposit and invest more, to rack up more profit, Thanks.`
      })
    }
  }
  catch (error) {
    console.log(error)
    res.json({ status: 'error', message: 'internal server error' })
  }
})

app.post('/api/sendproof', requireAuth, async (req, res) => {
  try {
    const email = req.tokenEmail
    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (user) {
      return res.json({
        status: 200,
        email: user.email,
        name: user.firstname,
        message: `Hi! you have successfully placed a deposit order, kindly exercise some patience as we verify your deposit. Your account will automatically be credited with $${req.body.amount} USD after verification.`,
        subject: 'Pending Deposit Alert',
        adminMessage: `hello BOSS, a user with the name.${user.firstname}, just deposited $${req.body.amount} USD into to your ${req.body.method} wallet. please confirm deposit and credit.`,
        adminSubject: 'Deposit Alert'
      })
    }
    else {
      return res.json({ status: 500 })
    }
  } catch (error) {
    console.log(error)
    res.json({ status: 404 })
  }
})



app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password, rememberme } = req.body;

    // Check if the user exists
    const user = await User.findOne({ email, deleted: { $ne: true } });
    if (!user) {
      return res.json({ status: 404, message: 'User does not exist' });
    }

    let passwordMatches = false;
    let needsRehash = false;

    if (typeof user.password === 'string' && user.password.startsWith('$2')) {
      passwordMatches = await bcrypt.compare(password, user.password);
    } else {
      // Legacy plaintext account: verify by equality, then silently upgrade
      // to a bcrypt hash on this successful match. No forced reset.
      passwordMatches = password === user.password;
      needsRehash = passwordMatches;
    }

    if (!passwordMatches) {
      return res.json({ status: 401, message: 'Incorrect password' });
    }

    if (needsRehash) {
      user.password = await bcrypt.hash(password, 10);
    }

    // Generate JWT token with user ID and email
    const token = jwt.sign(
      { id: user._id, email: user.email },
      jwtSecret,
      { expiresIn: '7d' } // Set token to expire in 7 days
    );

    // Update the user's "remember me" status (and persist any password rehash)
    user.rememberme = rememberme || false;
    await user.save();

    // Send response
    return res.status(200).json({
      status: 'ok',
      token,
      message: 'Login successful',
    });
  } catch (error) {
    console.error('Error during login:', error);
    return res.json({ status: 'error', message: 'Internal server error' });
  }
});


app.get('/api/getUsers', requireAdminAuth, async (req, res) => {
  const users = await User.find({ deleted: { $ne: true } }).select('-password')
  await logAudit(req, { action: 'list_users', success: true })
  res.json(users)
})

app.get('/api/admin/auditlog', requireAdminAuth, async (req, res) => {
  const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(500)
  res.json({ status: 200, logs })
})


app.post('/api/invest', requireAuth, async (req, res) => {
  try {
    const email = req.tokenEmail
    const user = await User.findOne({ email: email, deleted: { $ne: true } })
    if (!user) {
      return res.json({ status: 400, message: 'User not found' })
    }

    const investAmount = Number(req.body.amount)
    if (!isValidAmount(investAmount)) {
      return res.status(400).json({ status: 'error', message: 'Amount must be a positive number' })
    }

    const money = (() => {
      switch (req.body.percent) {
        case '20%':
          return (investAmount * 20) / 100
        case '35%':
          return (investAmount * 35) / 100
        case '50%':
          return (investAmount * 50) / 100
        case '65%':
          return (investAmount * 65) / 100
        case '80%':
          return (investAmount * 80) / 100
        case '100%':
          return (investAmount * 100) / 100
      }
    })()
    if (user.capital >= investAmount) {
      const now = new Date()
      await User.updateOne(
        { email: email },
        {
          $set: { capital: user.capital - investAmount, totalprofit: user.totalprofit + money, withdrawDuration: now.getTime() },
        }
      )
      await User.updateOne(
        { email: email },
        {
          $push: {
            investment:
            {
              type: 'investment',
              amount: investAmount,
              plan: req.body.plan,
              percent: req.body.percent,
              startDate: now.toLocaleString(),
              endDate: now.setDate(now.getDate() + 432000).toLocaleString(),
              profit: money,
              ended: 259200000,
              started: now.getTime(),
              periodicProfit: 0
            },
            transaction: {
              type: 'investment',
              amount: investAmount,
              date: now.toLocaleString(),
              balance: user.funded + investAmount,
              id: crypto.randomBytes(32).toString("hex")
            }
          }
        }
      )
      res.json({ status: 'ok', amount: investAmount })
    } else {
      res.json({
        message: 'Insufficient capital!',
        status: 400
      })
    }
  } catch (error) {
    return res.json({ status: 500, error: error })
  }
})


const change = (users, now) => {
  users.forEach((user) => {

    user.investment.forEach(async (invest) => {
      if (isNaN(invest.started)) {
        return
      }
      if (!user.investment || user.investment.length === 0) {
        return
      }
      if (now - invest.started >= invest.ended) {
        return
      }
      if (isNaN(invest.profit)) {
        return
      }
      else {
        try {
          await User.updateOne(
            { email: user.email },
            {
              $set: {
                funded: user.funded + invest.profit,
                periodicProfit: user.periodicProfit + invest.profit,
                capital: user.capital + invest.profit,
                totalProfit: user.totalProfit + invest.profit
              }
            }
          )
        } catch (error) {
          console.log(error)
        }
      }
    })
  })
}
app.get('/api/cron', requireCronOrAdmin, async (req, res) => {
  try {
    const users = (await User.find({ deleted: { $ne: true } })) ?? []
    const now = new Date().getTime()
    change(users, now)
    return res.json({ status: 200 })
  } catch (error) {
    console.log(error)
    return res.json({ status: 500, message: 'error! timeout' })
  }
})


app.post('/api/getWithdrawInfo', requireAdminAuth, async (req, res) => {
  const email = req.body.email
  try {
    const user = await User.findOne({
      email: email, deleted: { $ne: true }
    })

    if (user) {
      const userAmount = user.withdrawAmount
      await User.updateOne(
        { email: email },
        { $set: { funded: user.funded - userAmount, totalwithdraw: user.totalwithdraw + userAmount, capital: user.capital - userAmount, withdrawAmount: 0 } }
      )
      await User.updateOne(
        { email: email },
        {
          $push: {
            withdraw: {
              date: new Date().toLocaleString(),
              amount: userAmount,
              id: crypto.randomBytes(32).toString("hex"),
              balance: user.funded - userAmount
            }
          }
        }
      )
      const now = new Date()
      await User.updateOne(
        { email: email },
        {
          $push: {
            transaction: {
              type: 'withdraw',
              amount: userAmount,
              date: now.toLocaleString(),
              balance: user.funded - userAmount,
              id: crypto.randomBytes(32).toString("hex"),
            }
          }
        }
      )
      await logAudit(req, { action: 'approve_withdrawal', target: email, success: true, details: { amount: userAmount } })
      return res.json({ status: 'ok', amount: userAmount })
    } else {
      await logAudit(req, { action: 'approve_withdrawal', target: email, success: false, details: { reason: 'user not found' } })
      return res.json({ status: 'error', user: false })
    }
  }
  catch (err) {
    await logAudit(req, { action: 'approve_withdrawal', target: email, success: false, details: { error: String(err) } })
    return res.json({ status: 'error', user: false })
  }
})

// Create new trader
app.post('/api/createTrader', requireAdminAuth, async (req, res) => {
  try {
    const {
      firstname,
      lastname,
      nationality,
      winRate, // this doesn't exist in the model, maybe map to profitrate?
      avgReturn,
      followers,
      rrRatio,
      minimumcapital,
      traderImage
    } = req.body;

    const newTrader = new Trader({
      firstname,
      lastname,
      nationality,
      profitrate: winRate || '92%', // mapping winRate from frontend
      averagereturn: avgReturn || '90%',
      followers: followers || '50345',
      rrRatio: rrRatio || '1:7',
      minimumcapital: minimumcapital || 5000,
      tradehistory: [], // empty by default
      numberoftrades: '64535', // or set it dynamically later
      traderImage: traderImage
    });

    const savedTrader = await newTrader.save();
    await logAudit(req, { action: 'create_trader', target: String(savedTrader._id), success: true })
    res.status(201).json(savedTrader);
  } catch (error) {
    console.error('Error creating trader:', error);
    await logAudit(req, { action: 'create_trader', success: false, details: { error: String(error) } })
    res.status(500).json({ message: 'Server error', error });
  }
});

app.get('/api/fetchTraders', async (req, res) => {
  try {
    const traders = await Trader.find({ deleted: { $ne: true } })
    res.json({ status: 200, traders: traders })
  }
  catch (error) {
    res.json({ status: 404, error: error })
  }
})

app.get('/:id/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.id })
    if (!user) {
      return res.json({ status: 400 })
    }
    const token = await Token.findOne({ userId: user._id, token: req.params.token })

    if (!token) {
      return res.json({ status: 400 })
    }
    await User.updateOne({ _id: user._id }, {
      $set: { verified: true }
    })
    await token.remove()
    res.json({ status: 200 })
  } catch (error) {
    console.log(error)
    res.json({ status: `internal server error ${error}` })
  }
})


app.post('/api/requestpasswordreset', resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const genericResponse = { status: 'ok', message: 'If an account with that email exists, a reset link has been sent.' };

    if (!email) {
      return res.json(genericResponse);
    }

    const user = await User.findOne({ email, deleted: { $ne: true } });
    if (!user) {
      return res.json(genericResponse);
    }

    // Invalidate any previous outstanding tokens for this account.
    await PasswordResetToken.deleteMany({ userId: user._id });

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

    await PasswordResetToken.create({ userId: user._id, tokenHash });

    const resetLink = `https://www.signalsynch.com/resetpassword/${rawToken}`;

    return res.json({
      status: 'ok',
      email: user.email,
      name: user.firstname,
      resetLink,
      subject: 'Password Reset Request',
      message: `Click the link below to reset your password. This link expires in 15 minutes and can only be used once.`
    });
  } catch (error) {
    console.error('Error requesting password reset:', error);
    return res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.post('/api/resetpassword', resetLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ status: 'error', message: 'Token and new password are required' });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const resetToken = await PasswordResetToken.findOne({ tokenHash });

    if (!resetToken) {
      return res.status(400).json({ status: 'error', message: 'Invalid or expired reset token' });
    }

    const FIFTEEN_MINUTES = 15 * 60 * 1000;
    if (Date.now() - resetToken.createdAt.getTime() > FIFTEEN_MINUTES) {
      await resetToken.deleteOne();
      return res.status(400).json({ status: 'error', message: 'Reset token has expired' });
    }

    const user = await User.findById(resetToken.userId);
    if (!user) {
      await resetToken.deleteOne();
      return res.status(404).json({ status: 'error', message: 'User does not exist' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ _id: user._id }, { $set: { password: hashedPassword } });

    // Single-use: destroy the token immediately after a successful reset.
    await resetToken.deleteOne();

    return res.status(200).json({
      status: 'ok',
      message: 'Password reset successful',
    });
  } catch (error) {
    console.error('password not reset', error);
    return res.status(500).json({ status: 'error', message: 'password not reset' });
  }
});

// KYC Submission Endpoint
app.post('/api/submitKYC', requireAuth, async (req, res) => {
  try {
    const email = req.tokenEmail;

    const {
      middlename,
      dateOfBirth,
      nationality,
      city,
      address,
      employmentStatus,
      occupation,
      annualIncome,
      sourceOfFunds,
      investmentExperience,
      idType,
      idNumber,
      idExpiry,
      idDocumentFront,
      idDocumentBack,
      proofOfAddress,
      selfiePhoto
    } = req.body;

    // Update user with KYC data
    await User.updateOne(
      { email, deleted: { $ne: true } },
      {
        $set: {
          middlename,
          dateOfBirth,
          nationality,
          city,
          address,
          employmentStatus,
          occupation,
          annualIncome,
          sourceOfFunds,
          investmentExperience,
          idType,
          idNumber,
          idExpiry,
          idDocumentFront,
          idDocumentBack,
          proofOfAddress,
          selfiePhoto,
          kycStatus: 'processing',
          kycSubmittedDate: new Date().toLocaleString()
        }
      }
    );

    res.status(200).json({
      status: 'ok',
      message: 'KYC submitted successfully and is under review'
    });
  } catch (error) {
    console.error('Error submitting KYC:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Admin: Approve KYC
app.post('/api/admin/approveKYC', requireAdminAuth, async (req, res) => {
  const { email } = req.body;
  try {
    await User.updateOne(
      { email },
      {
        $set: {
          kycStatus: 'approved',
          kycApprovedDate: new Date().toLocaleString(),
          kycRejectionReason: ''
        }
      }
    );

    const user = await User.findOne({ email });

    await logAudit(req, { action: 'approve_kyc', target: email, success: true })

    res.status(200).json({
      status: 'ok',
      message: 'KYC approved successfully',
      userName: user.firstname,
      userEmail: user.email
    });
  } catch (error) {
    console.error('Error approving KYC:', error);
    await logAudit(req, { action: 'approve_kyc', target: email, success: false, details: { error: String(error) } })
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Admin: Reject KYC
app.post('/api/admin/rejectKYC', requireAdminAuth, async (req, res) => {
  const { email, reason } = req.body;
  try {
    await User.updateOne(
      { email },
      {
        $set: {
          kycStatus: 'rejected',
          kycRejectionReason: reason || 'Documents do not meet requirements',
          kycApprovedDate: ''
        }
      }
    );

    const user = await User.findOne({ email });

    await logAudit(req, { action: 'reject_kyc', target: email, success: true, details: { reason } })

    res.status(200).json({
      status: 'ok',
      message: 'KYC rejected',
      userName: user.firstname,
      userEmail: user.email
    });
  } catch (error) {
    console.error('Error rejecting KYC:', error);
    await logAudit(req, { action: 'reject_kyc', target: email, success: false, details: { error: String(error) } })
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});




module.exports = app
