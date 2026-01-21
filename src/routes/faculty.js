/**
 * Faculty Management Routes
 * GET /api/faculty - Get all faculty
 * GET /api/faculty/:id - Get faculty by ID
 * POST /api/faculty - Create faculty
 * PUT /api/faculty/:id - Update faculty
 * DELETE /api/faculty/:id - Delete faculty
 * GET /api/faculty/profile - Get faculty profile
 * POST /api/faculty/change-password - Change password
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const pool = require('../config/database');
const { authenticateToken, authorizeRole } = require('../middleware/auth');

// Get all faculty
router.get('/', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, username, email, department, specialization, phone, is_active 
             FROM faculty WHERE is_active = TRUE ORDER BY username`
        );
        res.json(result.rows || []);
    } catch (error) {
        console.error('Faculty GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get faculty by ID
router.get('/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM faculty WHERE id = $1', [req.params.id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Faculty not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get faculty profile (current user)
router.get('/profile/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM faculty WHERE id = $1', [req.user?.id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Faculty profile not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create faculty
router.post('/', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { username, email, password, department, specialization, phone } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO faculty (username, email, password, department, specialization, phone, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, TRUE)
             RETURNING id, username, email, department, specialization, phone`,
            [username, email, hashedPassword, department, specialization, phone]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update faculty
router.put('/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { username, email, department, specialization, phone } = req.body;

        const result = await pool.query(
            `UPDATE faculty 
             SET username = COALESCE($1, username),
                 email = COALESCE($2, email),
                 department = COALESCE($3, department),
                 specialization = COALESCE($4, specialization),
                 phone = COALESCE($5, phone)
             WHERE id = $6
             RETURNING *`,
            [username, email, department, specialization, phone, req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Faculty not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete faculty
router.delete('/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const result = await pool.query(
            'UPDATE faculty SET is_active = FALSE WHERE id = $1 RETURNING id',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Faculty not found' });
        }

        res.json({ message: 'Faculty deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Change password
router.post('/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const result = await pool.query('SELECT password FROM faculty WHERE id = $1', [req.user?.id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Faculty not found' });
        }

        const validPassword = await bcrypt.compare(currentPassword, result.rows[0].password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        await pool.query('UPDATE faculty SET password = $1 WHERE id = $2', [hashedPassword, req.user?.id]);

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;

module.exports = router;
