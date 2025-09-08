require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { body, validationResult, query, param } = require('express-validator');

const app = express();
app.use(cors());
app.use(express.json());

// --- JWT secret fallback ---
if (!process.env.JWT_SECRET) {
    console.warn('WARNING: JWT_SECRET is not set. Generating temporary secret (dev only).');
    process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
}

// --- Async wrapper ---
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// --- Mongo Models ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true, lowercase: true, index: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['hr'], default: 'hr' }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const candidateSchema = new mongoose.Schema({
    name: { type: String, required: true },
    role: { type: String, required: true },
    experience: { type: Number, required: true, min: 0 },
    rating: { type: Number, default: 0 },
    notes: { type: String, default: '' },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
const Candidate = mongoose.model('Candidate', candidateSchema);

const interviewSchema = new mongoose.Schema({
    candidate: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true },
    date: { type: Date, required: true },
    interviewer: { type: String, required: true },
    mode: { type: String, enum: ['onsite', 'remote'], default: 'remote' },
    feedback: { rating: Number, notes: String },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
const Interview = mongoose.model('Interview', interviewSchema);

// --- Error handler ---
app.use((err, req, res, next) => {
    if (err && err.name === 'MongoServerError' && err.code === 11000) {
        return res.status(400).json({ error: 'Duplicate key', details: err.keyValue });
    }
    console.error(err.stack || err);
    res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

// --- Auth middleware ---
function auth(requiredRole = 'hr') {
    return (req, res, next) => {
        const header = req.header('Authorization');
        if (!header) return res.status(401).json({ error: 'No token provided' });
        const token = header.replace('Bearer ', '');
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET);
            if (requiredRole && payload.role !== requiredRole) return res.status(403).json({ error: 'Forbidden' });
            req.user = payload;
            next();
        } catch (e) {
            return res.status(401).json({ error: 'Invalid token' });
        }
    };
}

// --- Validation ---
function checkValidation(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return false;
    }
    return true;
}

// --- Routes ---
// Health
app.get('/api/health', (req, res) => res.json({ ok: true, now: new Date() }));

// Auth: Signup
app.post('/api/auth/signup', [
    body('name').notEmpty().withMessage('Name required'),
    body('email').isEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 6 }).withMessage('Password min 6 chars')
], asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { name, email, password } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ error: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ name, email, passwordHash });
    await user.save();
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
}));

// Auth: Login
app.post('/api/auth/login', [
    body('email').isEmail(),
    body('password').notEmpty()
], asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
}));

// Create candidate
app.post('/api/candidates', auth('hr'), [
    body('name').notEmpty(),
    body('role').notEmpty(),
    body('experience').isNumeric()
], asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { name, role, experience, rating = 0, notes = '' } = req.body;
    const candidate = new Candidate({ name, role, experience: Number(experience), rating: Number(rating), notes, createdBy: req.user.userId });
    await candidate.save();
    res.status(201).json(candidate);
}));

// List candidates
app.get('/api/candidates', auth('hr'), asyncHandler(async (req, res) => {
    let { q, role, minExp, page = 1, limit } = req.query;
    const filter = {};
    if (q) filter.name = { $regex: q, $options: 'i' };
    if (role) filter.role = role;
    if (minExp) filter.experience = { $gte: Number(minExp) };

    page = Number(page) || 1;

    let candidatesQuery = Candidate.find(filter).sort({ createdAt: -1 });

    if (limit === 'all') {
        const data = await candidatesQuery;
        return res.json({ data, total: data.length });
    }

    limit = Math.min(Number(limit) || 10, 100);
    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
        candidatesQuery.skip(skip).limit(limit),
        Candidate.countDocuments(filter)
    ]);

    res.json({ data, total });
}));

// Candidate details
app.get('/api/candidates/:id', auth('hr'), [
    param('id').isMongoId()
], asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const candidate = await Candidate.findById(req.params.id);
    if (!candidate) return res.status(404).json({ error: 'Candidate not found' });
    res.json(candidate);
}));

// Schedule interview
app.post('/api/interviews', auth('hr'), [
    body('candidate').isMongoId(),
    body('date').notEmpty(),
    body('interviewer').notEmpty(),
    body('mode').optional().isIn(['onsite', 'remote'])
], asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { candidate, date, interviewer, mode = 'remote' } = req.body;
    if (!await Candidate.findById(candidate)) return res.status(404).json({ error: 'Candidate not found' });
    const iv = new Interview({ candidate, date: new Date(date), interviewer, mode, createdBy: req.user.userId });
    await iv.save();
    res.status(201).json(iv);
}));

// List interviews
app.get('/api/interviews', auth('hr'), asyncHandler(async (req, res) => {
    let { candidateId, page = 1, limit } = req.query;
    const filter = {};
    if (candidateId) filter.candidate = candidateId;
    page = Number(page) || 1;

    let interviewsQuery = Interview.find(filter).populate('candidate').sort({ date: -1 });

    if (limit === 'all') {
        const data = await interviewsQuery;
        return res.json({ data, total: data.length });
    }

    limit = Math.min(Number(limit) || 10, 100);
    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
        interviewsQuery.skip(skip).limit(limit),
        Interview.countDocuments(filter)
    ]);

    res.json({ data, total });
}));

// Add/update feedback
app.post('/api/interviews/:id/feedback', auth('hr'), [
    param('id').isMongoId(),
    body('rating').optional().isNumeric(),
    body('notes').optional().isString()
], asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const iv = await Interview.findById(req.params.id);
    if (!iv) return res.status(404).json({ error: 'Interview not found' });
    iv.feedback = {};
    if (req.body.rating !== undefined) iv.feedback.rating = Number(req.body.rating);
    if (req.body.notes !== undefined) iv.feedback.notes = req.body.notes;
    await iv.save();
    res.json(iv);
}));

// Fallback 404
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Start server
const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGO_URI)
    .then(() => app.listen(PORT, () => console.log(`Server running on ${PORT}`)))
    .catch(err => { console.error('Mongo connection error:', err); process.exit(1); });
