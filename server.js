require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');


const app = express();

// =====================================================
// DATABASE CONFIG
// =====================================================
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD || null,
  port: process.env.DB_PORT,
});

pool.query('SELECT 1')
  .then(() => console.log('✅ Database connected'))
  .catch(err => console.error('❌ Database failed:', err.message));

app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey2026";
const PORT = 5001;

// Helper function to format time to HH:MM AM/PM
function formatTimeToAMPM(timestamp) {
  if (!timestamp) return '—';
  const date = new Date(timestamp);
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });
}

// Helper function to format time for history (without seconds)
function formatHistoryTime(timestamp) {
  if (!timestamp) return '—';
  const date = new Date(timestamp);
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('en-IN', {
    hour: '2-digit',
    minute: '2-digit'
  });
}

// =====================================================
// HEALTH CHECK
// =====================================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// =====================================================
// LOGIN
// =====================================================
app.post('/api/login', async (req, res) => {
  const { mobile_no, password } = req.body;
  
  if (!mobile_no || !password) {
    return res.status(400).json({ error: 'Mobile & password required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE mobile_no = $1', [mobile_no]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, mobile_no: user.mobile_no, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, mobile_no: user.mobile_no, name: user.name, role: user.role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// =====================================================
// TEACHERS - Add
// =====================================================
app.post('/api/teachers/add', async (req, res) => {
  console.log('📝 Add Teacher Request:', req.body);
  
  const { mobile_no, name, password } = req.body;
  
  if (!mobile_no || !name || !password) {
    return res.status(400).json({ 
      error: 'Missing fields',
      required: ['mobile_no', 'name', 'password']
    });
  }

  try {
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE mobile_no = $1',
      [mobile_no]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Mobile number already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (mobile_no, password_hash, role, name) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, mobile_no, name, role, created_at`,
      [mobile_no, hashedPassword, 'teacher', name]
    );
    
    const newTeacher = result.rows[0];
    console.log('✅ Teacher added:', newTeacher);
    
    res.status(201).json({
      success: true,
      message: `Teacher ${name} added successfully`,
      teacher: newTeacher
    });
    
  } catch (error) {
    console.error('❌ Add teacher error:', error);
    res.status(500).json({ 
      error: 'Failed to add teacher',
      details: error.message 
    });
  }
});

// =====================================================
// TEACHERS - List all teachers
// =====================================================
app.get('/api/teachers', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, mobile_no, name, created_at 
       FROM users 
       WHERE role = 'teacher' 
       ORDER BY name ASC`
    );
    
    res.json({
      success: true,
      teachers: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error('❌ Fetch teachers error:', error);
    res.status(500).json({ error: 'Failed to fetch teachers' });
  }
});

// =====================================================
// TEACHERS - Delete teacher
// =====================================================
app.delete('/api/teachers/:id', async (req, res) => {
  const teacherId = req.params.id;
  
  try {
    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 AND role = $2 RETURNING id, name',
      [teacherId, 'teacher']
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Teacher not found' });
    }
    
    res.json({
      success: true,
      message: `Teacher ${result.rows[0].name} deleted successfully`,
      deletedTeacher: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Delete teacher error:', error);
    res.status(500).json({ error: 'Failed to delete teacher' });
  }
});

// =====================================================
// PRINCIPAL - Save/Update PIN (Receives PIN from frontend)
// =====================================================
app.post('/api/principal/save-pin', async (req, res) => {
  const { pin_code } = req.body;
  const today = new Date().toISOString().split('T')[0];
  
  if (!pin_code || pin_code.length !== 4) {
    return res.status(400).json({ error: 'Valid 4-digit PIN required' });
  }
  
  try {
    const result = await pool.query(`
      INSERT INTO daily_attendance_pins (pin_code, pin_date, valid_from, valid_until, is_active)
      VALUES ($1, $2, '08:00:00', '10:30:00', true)
      ON CONFLICT (pin_date) 
      DO UPDATE SET 
        pin_code = EXCLUDED.pin_code,
        valid_from = EXCLUDED.valid_from,
        valid_until = EXCLUDED.valid_until,
        is_active = true,
        created_at = CURRENT_TIMESTAMP
      RETURNING pin_code, pin_date, valid_from, valid_until
    `, [pin_code, today]);
    
    res.json({
      success: true,
      pin: result.rows[0].pin_code,
      date: today,
      valid_from: result.rows[0].valid_from,
      valid_until: result.rows[0].valid_until,
      message: `PIN ${pin_code} saved successfully`
    });
  } catch (error) {
    console.error('Save PIN error:', error);
    res.status(500).json({ error: 'Failed to save PIN' });
  }
});

// =====================================================
// PRINCIPAL - Get Today's PIN
// =====================================================
app.get('/api/principal/today-pin', async (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  
  try {
    const result = await pool.query(`
      SELECT pin_code, pin_date, valid_from, valid_until, is_active
      FROM daily_attendance_pins
      WHERE pin_date = $1
    `, [today]);
    
    if (result.rows.length === 0) {
      return res.json({ success: true, pin: null });
    }
    
    res.json({
      success: true,
      pin: result.rows[0].pin_code,
      valid_from: result.rows[0].valid_from,
      valid_until: result.rows[0].valid_until,
      is_active: result.rows[0].is_active
    });
  } catch (error) {
    console.error('Get PIN error:', error);
    res.status(500).json({ error: 'Failed to get PIN' });
  }
});

// =====================================================
// TEACHER - Mark Attendance (Handles both IN and OUT)
// =====================================================
app.post('/api/teacher-attendance/mark', async (req, res) => {
  const { teacher_id, pin_code } = req.body;
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  const currentTime = now.toTimeString().split(' ')[0];
  
  try {
    // Verify PIN
    const pinResult = await pool.query(`
      SELECT * FROM daily_attendance_pins 
      WHERE pin_date = $1 
      AND pin_code = $2
      AND valid_from <= $3
      AND valid_until >= $3
      AND is_active = true
    `, [today, pin_code, currentTime]);
    
    if (pinResult.rows.length === 0) {
      return res.status(400).json({ 
        error: 'Invalid PIN or outside allowed time window (8:00 AM - 10:30 AM)' 
      });
    }
    
    // Check existing attendance
    const existing = await pool.query(`
      SELECT * FROM teacher_attendance 
      WHERE teacher_id = $1 AND attendance_date = $2
    `, [teacher_id, today]);
    
    // Case 1: No record yet → Mark IN time
    if (existing.rows.length === 0) {
      const isLate = currentTime > '09:00:00';
      const status = isLate ? 'late' : 'present';
      
      await pool.query(`
        INSERT INTO teacher_attendance (teacher_id, attendance_date, pin_code, in_time, status)
        VALUES ($1, $2, $3, $4, $5)
      `, [teacher_id, today, pin_code, now, status]);
      
      return res.json({
        success: true,
        action: 'IN',
        message: `✅ IN time marked at ${now.toLocaleTimeString()}`,
        status: isLate ? '⚠️ Late arrival' : '✅ On time'
      });
    }
    
    // Case 2: Has IN but no OUT → Mark OUT time
    if (existing.rows[0].in_time && !existing.rows[0].out_time) {
      await pool.query(`
        UPDATE teacher_attendance 
        SET out_time = $1
        WHERE teacher_id = $2 AND attendance_date = $3
      `, [now, teacher_id, today]);
      
      return res.json({
        success: true,
        action: 'OUT',
        message: `✅ OUT time marked at ${now.toLocaleTimeString()}`
      });
    }
    
    // Case 3: Both already marked
    if (existing.rows[0].in_time && existing.rows[0].out_time) {
      return res.status(400).json({ 
        error: 'Attendance already completed for today'
      });
    }
    
  } catch (error) {
    console.error('Attendance error:', error);
    res.status(500).json({ error: 'Failed to mark attendance' });
  }
});

// =====================================================
// TEACHER - Get Today's Attendance Status
// =====================================================
app.get('/api/teacher-attendance/today', async (req, res) => {
  const teacher_id = req.query.teacher_id;
  const today = new Date().toISOString().split('T')[0];
  
  try {
    const result = await pool.query(`
      SELECT in_time, out_time, status
      FROM teacher_attendance
      WHERE teacher_id = $1 AND attendance_date = $2
    `, [teacher_id, today]);
    
    if (result.rows.length === 0) {
      return res.json({ success: true, attendance: null });
    }
    
    res.json({
      success: true,
      attendance: result.rows[0]
    });
  } catch (error) {
    console.error('Get attendance error:', error);
    res.status(500).json({ error: 'Failed to get attendance' });
  }
});

// =====================================================
// PRINCIPAL - Get Today's Attendance Report
// =====================================================
app.get('/api/principal/today-attendance', async (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  
  try {
    const teachersResult = await pool.query(`
      SELECT id, name FROM users WHERE role = 'teacher' ORDER BY name ASC
    `);
    
    const attendanceResult = await pool.query(`
      SELECT teacher_id, in_time, out_time, status
      FROM teacher_attendance
      WHERE attendance_date = $1
    `, [today]);
    
    const attendance = teachersResult.rows.map(teacher => {
      const att = attendanceResult.rows.find(a => a.teacher_id === teacher.id);
      
      return {
        name: teacher.name,
        in_time: att?.in_time ? formatTimeToAMPM(att.in_time) : '—',
        out_time: att?.out_time ? formatTimeToAMPM(att.out_time) : '—',
        status: att?.status || 'absent',
        date: today
      };
    });
    
    const present = attendance.filter(a => a.status === 'present').length;
    const absent = attendance.filter(a => a.status === 'absent').length;
    const late = attendance.filter(a => a.status === 'late').length;
    
    res.json({
      success: true,
      date: today,
      attendance,
      summary: {
        total: teachersResult.rows.length,
        present,
        absent,
        late,
        attendance_percentage: teachersResult.rows.length > 0 ? ((present / teachersResult.rows.length) * 100).toFixed(1) : '0'
      }
    });
  } catch (error) {
    console.error('Report error:', error);
    res.status(500).json({ error: 'Failed to fetch attendance report' });
  }
});

// =====================================================
// PRINCIPAL - Get Attendance by Date
// =====================================================
app.get('/api/principal/attendance-by-date', async (req, res) => {
  const { date } = req.query;
  
  if (!date) {
    return res.status(400).json({ error: 'Date is required' });
  }
  
  try {
    const teachersResult = await pool.query(`
      SELECT id, name FROM users WHERE role = 'teacher' ORDER BY name ASC
    `);
    
    const attendanceResult = await pool.query(`
      SELECT teacher_id, in_time, out_time, status
      FROM teacher_attendance
      WHERE attendance_date = $1
    `, [date]);
    
    const attendance = teachersResult.rows.map(teacher => {
      const att = attendanceResult.rows.find(a => a.teacher_id === teacher.id);
      
      return {
        name: teacher.name,
        in_time: att?.in_time ? formatTimeToAMPM(att.in_time) : '—',
        out_time: att?.out_time ? formatTimeToAMPM(att.out_time) : '—',
        status: att?.status || 'absent',
        date: date
      };
    });
    
    const present = attendance.filter(a => a.status === 'present').length;
    const absent = attendance.filter(a => a.status === 'absent').length;
    const late = attendance.filter(a => a.status === 'late').length;
    
    res.json({
      success: true,
      date,
      attendance,
      summary: {
        total: teachersResult.rows.length,
        present,
        absent,
        late,
        attendance_percentage: teachersResult.rows.length > 0 ? ((present / teachersResult.rows.length) * 100).toFixed(1) : '0'
      }
    });
  } catch (error) {
    console.error('Report error:', error);
    res.status(500).json({ error: 'Failed to fetch attendance report' });
  }
});
// =====================================================
// TEACHER - Get Attendance History (Last 7 days)
// =====================================================
app.get('/api/teacher/attendance-history', async (req, res) => {
  const teacher_id = req.query.teacher_id;
  const days = parseInt(req.query.days) || 7;
  
  if (!teacher_id) {
    return res.status(400).json({ error: 'Teacher ID required' });
  }
  
  try {
    // Get attendance records from database only (no filler logic)
    const result = await pool.query(`
      SELECT attendance_date, in_time, out_time, status
      FROM teacher_attendance
      WHERE teacher_id = $1 
      ORDER BY attendance_date DESC
      LIMIT $2
    `, [teacher_id, days]);
    
    // Format the records
    const daysOfWeek = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const history = result.rows.map(record => {
      const date = new Date(record.attendance_date);
      const day = daysOfWeek[date.getDay()];
      const fullDate = date.toLocaleDateString('en-IN', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
      });
      
      return {
        date: record.attendance_date,
        full_date: fullDate,
        day: day,
        in_time: record.in_time ? formatHistoryTime(record.in_time) : '—',
        out_time: record.out_time ? formatHistoryTime(record.out_time) : '—',
        status: record.status || 'present'
      };
    });
    
    res.json({
      success: true,
      attendance: history
    });
  } catch (error) {
    console.error('History error:', error);
    res.status(500).json({ error: 'Failed to fetch attendance history' });
  }
});

// =====================================================
// PRINCIPAL - Teacher-wise Attendance Report
// =====================================================
app.get('/api/principal/reports/teacher-attendance', async (req, res) => {
  const { period } = req.query;
  const days = period === 'week' ? 7 : period === 'month' ? 30 : 365;
  
  try {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    
    const teachersResult = await pool.query(`
      SELECT id, name FROM users WHERE role = 'teacher' ORDER BY name ASC
    `);
    
    const attendanceResult = await pool.query(`
      SELECT teacher_id, status, COUNT(*) as count
      FROM teacher_attendance
      WHERE attendance_date >= $1
      GROUP BY teacher_id, status
    `, [startDate]);
    
    const teachers = teachersResult.rows.map(teacher => {
      const teacherAttendance = attendanceResult.rows.filter(a => a.teacher_id === teacher.id);
      const present = teacherAttendance.find(a => a.status === 'present')?.count || 0;
      const absent = teacherAttendance.find(a => a.status === 'absent')?.count || 0;
      const late = teacherAttendance.find(a => a.status === 'late')?.count || 0;
      const total = present + absent + late;
      const percentage = total > 0 ? ((present / total) * 100).toFixed(1) : 0;
      
      return {
        name: teacher.name,
        attendance_percentage: parseFloat(percentage),
        present,
        absent,
        late,
        total_days: total
      };
    });
    
    const totalPresent = teachers.reduce((sum, t) => sum + t.present, 0);
    const totalAbsent = teachers.reduce((sum, t) => sum + t.absent, 0);
    const totalLate = teachers.reduce((sum, t) => sum + t.late, 0);
    const totalDays = totalPresent + totalAbsent;
    const overallPercentage = totalDays > 0 ? ((totalPresent / totalDays) * 100).toFixed(1) : 0;
    
    res.json({
      success: true,
      teachers,
      summary: {
        total_teachers: teachers.length,
        overall_percentage: parseFloat(overallPercentage),
        total_present: totalPresent,
        total_absent: totalAbsent,
        total_late: totalLate
      }
    });
  } catch (error) {
    console.error('Report error:', error);
    res.status(500).json({ error: 'Failed to fetch report' });
  }
});

/// =====================================================
// PRINCIPAL - Monthly Attendance Report
// =====================================================
app.get('/api/principal/reports/monthly', async (req, res) => {
  const { year, month } = req.query;
  
  if (!year || !month) {
    return res.status(400).json({ error: 'Year and month are required' });
  }
  
  try {
    // Get start and end date of the month
    const startDate = new Date(year, month - 1, 1);
    const endDate = new Date(year, month, 0);
    
    // Get all teachers
    const teachersResult = await pool.query(`
      SELECT id, name FROM users WHERE role = 'teacher' ORDER BY name ASC
    `);
    
    // Get attendance for the month
    const attendanceResult = await pool.query(`
      SELECT teacher_id, status, COUNT(*) as count
      FROM teacher_attendance
      WHERE attendance_date >= $1 AND attendance_date <= $2
      GROUP BY teacher_id, status
    `, [startDate, endDate]);
    
    const teachers = teachersResult.rows.map(teacher => {
      const teacherAttendance = attendanceResult.rows.filter(a => a.teacher_id === teacher.id);
      const present = teacherAttendance.find(a => a.status === 'present')?.count || 0;
      const absent = teacherAttendance.find(a => a.status === 'absent')?.count || 0;
      const late = teacherAttendance.find(a => a.status === 'late')?.count || 0;
      const total = present + absent + late;
      const percentage = total > 0 ? ((present / total) * 100).toFixed(1) : 0;
      
      return {
        name: teacher.name,
        attendance_percentage: parseFloat(percentage),
        present,
        absent,
        late,
        total_days: total
      };
    });
    
    const totalPresent = teachers.reduce((sum, t) => sum + t.present, 0);
    const totalAbsent = teachers.reduce((sum, t) => sum + t.absent, 0);
    const totalLate = teachers.reduce((sum, t) => sum + t.late, 0);
    const totalDays = totalPresent + totalAbsent;
    const overallPercentage = totalDays > 0 ? ((totalPresent / totalDays) * 100).toFixed(1) : 0;
    
    res.json({
      success: true,
      teachers,
      summary: {
        total_teachers: teachers.length,
        overall_percentage: parseFloat(overallPercentage),
        total_present: totalPresent,
        total_absent: totalAbsent,
        total_late: totalLate
      }
    });
  } catch (error) {
    console.error('Monthly report error:', error);
    res.status(500).json({ error: 'Failed to fetch monthly report' });
  }
});

// =====================================================
// START SERVER
// =====================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Server running on port ${PORT}`);
  console.log(`📍 Local: http://localhost:${PORT}`);
  console.log(`🌐 Network: http://YOUR_IP:${PORT}`);
  console.log(`\n📋 Available endpoints:`);
  console.log(`   POST   /api/login`);
  console.log(`   POST   /api/teachers/add`);
  console.log(`   GET    /api/teachers`);
  console.log(`   DELETE /api/teachers/:id`);
  console.log(`   POST   /api/principal/save-pin`);
  console.log(`   GET    /api/principal/today-pin`);
  console.log(`   GET    /api/principal/today-attendance`);
  console.log(`   GET    /api/principal/attendance-by-date`);
  console.log(`   POST   /api/teacher-attendance/mark`);
  console.log(`   GET    /api/teacher-attendance/today`);
  console.log(`   GET    /api/teacher/attendance-history`);
  console.log(`   GET    /api/health\n`);
});