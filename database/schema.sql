-- Smart Classroom Scheduler Database Schema
-- PostgreSQL Database Setup

-- Drop existing tables if they exist (for fresh setup)
DROP TABLE IF EXISTS swap_requests CASCADE;
DROP TABLE IF EXISTS timetable CASCADE;
DROP TABLE IF EXISTS faculty_subjects CASCADE;
DROP TABLE IF EXISTS leave_requests CASCADE;
DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS subjects CASCADE;
DROP TABLE IF EXISTS students CASCADE;
DROP TABLE IF EXISTS faculty CASCADE;
DROP TABLE IF EXISTS rooms CASCADE;
DROP TABLE IF EXISTS users CASCADE;




-- Create Users table (Authentication)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'faculty', 'student')),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Faculty table
CREATE TABLE faculty (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(15),
    department VARCHAR(50) NOT NULL,
    designation VARCHAR(50),
    hire_date DATE,
    is_active BOOLEAN DEFAULT TRUE,
    max_hours_per_week INTEGER DEFAULT 25,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Students table
CREATE TABLE students (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    roll_number VARCHAR(20) UNIQUE,
    batch VARCHAR(20) NOT NULL,
    semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 8),
    department VARCHAR(50) NOT NULL,
    phone VARCHAR(15),
    address TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Rooms table
CREATE TABLE rooms (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('Classroom', 'Lab', 'Auditorium', 'Seminar Hall')),
    capacity INTEGER NOT NULL CHECK (capacity > 0),
    department VARCHAR(50),
    building VARCHAR(50),
    floor INTEGER,
    location TEXT,
    facilities TEXT[], -- Array of facilities like 'Projector', 'AC', 'Whiteboard'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Subjects table
CREATE TABLE subjects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    department VARCHAR(50) NOT NULL,
    semester INTEGER CHECK (semester BETWEEN 1 AND 8),
    credits INTEGER NOT NULL CHECK (credits > 0),
    type VARCHAR(20) NOT NULL CHECK (type IN ('Theory', 'Practical', 'Tutorial')),
    description TEXT,
    prerequisites TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Faculty-Subjects mapping table
CREATE TABLE faculty_subjects (
    id SERIAL PRIMARY KEY,
    faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
    subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
    subject_name VARCHAR(100) NOT NULL, -- For backward compatibility
    is_primary BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(faculty_id, subject_id)
);

-- Create Timetable table
CREATE TABLE timetable (
    id SERIAL PRIMARY KEY,
    batch VARCHAR(20) NOT NULL,
    subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
    faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
    room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    day_of_week VARCHAR(10) NOT NULL CHECK (day_of_week IN ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')),
    time_slot VARCHAR(20) NOT NULL, -- Format: 'HH:MM-HH:MM'
    duration_minutes INTEGER DEFAULT 60,
    session_type VARCHAR(20) DEFAULT 'Lecture' CHECK (session_type IN ('Lecture', 'Lab', 'Tutorial', 'Seminar')),
    semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 8),
    academic_year VARCHAR(10) NOT NULL, -- Format: '2023-24'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(day_of_week, time_slot, room_id, academic_year),
    UNIQUE(day_of_week, time_slot, faculty_id, academic_year)
);

-- Create Leave Requests table
-- Create/Update leave_requests table
DROP TRIGGER IF EXISTS trigger_auto_reschedule ON leave_requests;
DROP FUNCTION IF EXISTS handle_faculty_leave(integer, date, date, integer);
DROP FUNCTION IF EXISTS trigger_auto_reschedule();

-- Step 2: Drop and recreate the leave_requests table with correct schema
DROP TABLE IF EXISTS leave_requests CASCADE;

CREATE TABLE leave_requests (
    id SERIAL PRIMARY KEY,
    faculty_id INTEGER NOT NULL,
    leave_type VARCHAR(50) NOT NULL DEFAULT 'Casual',
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' 
        CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    admin_notes TEXT,
    auto_rescheduled BOOLEAN DEFAULT FALSE,
    reschedule_details JSONB,
    reviewed_at TIMESTAMP,
    approved_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (faculty_id) REFERENCES faculty(id) ON DELETE CASCADE,
    FOREIGN KEY (approved_by) REFERENCES users(id)
);

-- Step 3: Create indexes for performance
CREATE INDEX idx_leave_requests_faculty_id ON leave_requests(faculty_id);
CREATE INDEX idx_leave_requests_status ON leave_requests(status);
CREATE INDEX idx_leave_requests_dates ON leave_requests(start_date, end_date);
CREATE INDEX idx_leave_requests_created ON leave_requests(created_at DESC);

-- Step 4: Grant permissions if needed
GRANT ALL PRIVILEGES ON leave_requests TO scheduler_user;
GRANT USAGE, SELECT ON SEQUENCE leave_requests_id_seq TO scheduler_user;

-- Step 5: Verify table structure
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'leave_requests' 
ORDER BY ordinal_position;

-- If you want to add a comment to the table
COMMENT ON TABLE leave_requests IS 'Faculty leave requests with automatic rescheduling support';
COMMENT ON COLUMN leave_requests.affected_classes_count IS 'Calculated dynamically from timetable, not stored';



-- Create Swap Requests table
CREATE TABLE swap_requests (
    id SERIAL PRIMARY KEY,
    requesting_faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
    target_faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
    original_timetable_id INTEGER REFERENCES timetable(id) ON DELETE CASCADE,
    requested_day VARCHAR(10) NOT NULL,
    requested_time_slot VARCHAR(20) NOT NULL,
    original_time_slot VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    admin_notes TEXT,
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Notifications table
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(30) NOT NULL CHECK (type IN ('timetable_update', 'swap_request', 'leave_request', 'general', 'system')),
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    priority VARCHAR(10) DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    related_id INTEGER, -- ID of related entity (timetable, swap_request, etc.)
    metadata JSONB, -- Additional data as JSON
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Audit Log table
-- CREATE TABLE audit_log (
--     id SERIAL PRIMARY KEY,
--     user_id INTEGER REFERENCES users(id),
--     action VARCHAR(50) NOT NULL,
--     table_name VARCHAR(50) NOT NULL,
--     record_id INTEGER,
--     old_values JSONB,
--     new_values JSONB,
--     ip_address INET,
--     user_agent TEXT,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );

-- Create Conflicts table (for tracking timetable conflicts)
CREATE OR REPLACE VIEW v_timetable_conflicts AS
-- REQUIREMENT 3: Faculty Double Booking Detection
SELECT 
    'Faculty Double Booking' as conflict_type,
    f.name as resource_name,
    t1.batch || ' & ' || t2.batch as affected_batches,
    t1.day_of_week, t1.time_slot,
    s1.name || ' vs ' || s2.name as conflicting_subjects,
    'high' as severity,
    t1.academic_year
FROM timetable t1
JOIN timetable t2 ON t1.faculty_id = t2.faculty_id 
    AND t1.day_of_week = t2.day_of_week 
    AND t1.time_slot = t2.time_slot
    AND t1.academic_year = t2.academic_year
    AND t1.id < t2.id
JOIN faculty f ON t1.faculty_id = f.id
JOIN subjects s1 ON t1.subject_id = s1.id
JOIN subjects s2 ON t2.subject_id = s2.id
WHERE t1.is_active = TRUE AND t2.is_active = TRUE

UNION ALL

-- REQUIREMENT 2: Room Double Booking Detection
SELECT 
    'Room Double Booking' as conflict_type,
    r.name as resource_name,
    t1.batch || ' & ' || t2.batch as affected_batches,
    t1.day_of_week, t1.time_slot,
    s1.name || ' vs ' || s2.name as conflicting_subjects,
    'high' as severity,
    t1.academic_year
FROM timetable t1
JOIN timetable t2 ON t1.room_id = t2.room_id 
    AND t1.day_of_week = t2.day_of_week 
    AND t1.time_slot = t2.time_slot
    AND t1.academic_year = t2.academic_year
    AND t1.id < t2.id
JOIN rooms r ON t1.room_id = r.id
JOIN subjects s1 ON t1.subject_id = s1.id
JOIN subjects s2 ON t2.subject_id = s2.id
WHERE t1.is_active = TRUE AND t2.is_active = TRUE

UNION ALL

-- REQUIREMENT 4: Lab Room Type Mismatch Detection
SELECT 
    'Lab Room Type Mismatch' as conflict_type,
    r.name as resource_name,
    t.batch as affected_batches,
    t.day_of_week, t.time_slot,
    s.name || ' (Type: ' || s.type || ', Room: ' || r.type || ')' as conflicting_subjects,
    'medium' as severity,
    t.academic_year
FROM timetable t
JOIN subjects s ON t.subject_id = s.id
JOIN rooms r ON t.room_id = r.id
WHERE t.is_active = TRUE
AND (
    (s.type = 'Practical' AND r.type != 'Lab')
    OR (s.type != 'Practical' AND r.type = 'Lab')
);

CREATE OR REPLACE VIEW v_batch_timetable_summary AS
SELECT 
    t.batch,
    t.academic_year,
    COUNT(DISTINCT t.id) as total_classes,
    COUNT(DISTINCT t.subject_id) as unique_subjects,
    COUNT(DISTINCT t.faculty_id) as faculty_count,
    COUNT(DISTINCT t.room_id) as room_count,
    COUNT(DISTINCT t.day_of_week) as days_utilized,
    ROUND(AVG(r.capacity), 0) as avg_room_capacity,
    SUM(t.duration_minutes) / 60.0 as total_weekly_hours,
    SUM(s.credits) as total_credits
FROM timetable t
JOIN subjects s ON t.subject_id = s.id
JOIN rooms r ON t.room_id = r.id
WHERE t.is_active = TRUE
GROUP BY t.batch, t.academic_year;

-- Create Academic Calendar table
-- CREATE TABLE academic_calendar (
--     id SERIAL PRIMARY KEY,
--     academic_year VARCHAR(10) NOT NULL,
--     semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 8),
--     start_date DATE NOT NULL,
--     end_date DATE NOT NULL,
--     exam_start_date DATE,
--     exam_end_date DATE,
--     holidays JSONB, -- JSON array of holiday dates and descriptions
--     is_active BOOLEAN DEFAULT TRUE,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     UNIQUE(academic_year, semester)
-- );

-- ==================== INDEXES ====================\

-- Users indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- Faculty indexes
CREATE INDEX idx_faculty_department ON faculty(department);
CREATE INDEX idx_faculty_email ON faculty(email);
CREATE INDEX idx_faculty_active ON faculty(is_active);

-- Students indexes
CREATE INDEX idx_students_batch ON students(batch);
CREATE INDEX idx_students_department ON students(department);
CREATE INDEX idx_students_semester ON students(semester);

-- Rooms indexes
CREATE INDEX idx_rooms_type ON rooms(type);
CREATE INDEX idx_rooms_department ON rooms(department);
CREATE INDEX idx_rooms_active ON rooms(is_active);

-- Subjects indexes
CREATE INDEX idx_subjects_code ON subjects(code);
CREATE INDEX idx_subjects_department ON subjects(department);
CREATE INDEX idx_subjects_semester ON subjects(semester);

-- Faculty-Subjects indexes
CREATE INDEX idx_faculty_subjects_faculty ON faculty_subjects(faculty_id);
CREATE INDEX idx_faculty_subjects_subject ON faculty_subjects(subject_id);

-- Timetable indexes
CREATE INDEX idx_timetable_batch ON timetable(batch);
CREATE INDEX idx_timetable_faculty ON timetable(faculty_id);
CREATE INDEX idx_timetable_room ON timetable(room_id);
CREATE INDEX idx_timetable_subject ON timetable(subject_id);
CREATE INDEX idx_timetable_day_time ON timetable(day_of_week, time_slot);
CREATE INDEX idx_timetable_academic_year ON timetable(academic_year);

-- Notifications indexes
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_read ON notifications(is_read);
CREATE INDEX idx_notifications_type ON notifications(type);

-- Audit log indexes
-- CREATE INDEX idx_audit_log_user ON audit_log(user_id);
-- CREATE INDEX idx_audit_log_action ON audit_log(action);
-- CREATE INDEX idx_audit_log_table ON audit_log(table_name);
-- CREATE INDEX idx_audit_log_created ON audit_log(created_at);

CREATE INDEX IF NOT EXISTS idx_timetable_faculty_day_time 
    ON timetable(faculty_id, day_of_week, time_slot, academic_year) 
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_timetable_room_day_time 
    ON timetable(room_id, day_of_week, time_slot, academic_year) 
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_timetable_batch_day_time 
    ON timetable(batch, day_of_week, time_slot, academic_year) 
    WHERE is_active = TRUE;

-- Optimize workload queries
CREATE INDEX IF NOT EXISTS idx_timetable_batch_academic_year 
    ON timetable(batch, academic_year, is_active);

-- Optimize elective queries
CREATE INDEX IF NOT EXISTS idx_subjects_name_elective 
    ON subjects(name) 
    WHERE name ILIKE '%elective%';

-- ==================== FUNCTIONS & TRIGGERS ====================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_faculty_updated_at BEFORE UPDATE ON faculty FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_students_updated_at BEFORE UPDATE ON students FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_rooms_updated_at BEFORE UPDATE ON rooms FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_subjects_updated_at BEFORE UPDATE ON subjects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_timetable_updated_at BEFORE UPDATE ON timetable FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_leave_requests_updated_at BEFORE UPDATE ON leave_requests FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_swap_requests_updated_at BEFORE UPDATE ON swap_requests FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to detect and log conflicts
CREATE OR REPLACE FUNCTION detect_timetable_conflicts()
RETURNS TRIGGER AS $$
BEGIN
    -- Check for faculty double booking
    IF EXISTS (
        SELECT 1 FROM timetable 
        WHERE faculty_id = NEW.faculty_id 
        AND day_of_week = NEW.day_of_week 
        AND time_slot = NEW.time_slot 
        AND academic_year = NEW.academic_year
        AND id != COALESCE(NEW.id, 0)
        AND is_active = TRUE
    ) THEN
        INSERT INTO conflicts (conflict_type, description, severity, timetable_id_1, timetable_id_2)
        SELECT 'faculty_double_booking', 
               'Faculty is assigned to multiple classes at the same time',
               'high',
               NEW.id,
               t.id
        FROM timetable t 
        WHERE t.faculty_id = NEW.faculty_id 
        AND t.day_of_week = NEW.day_of_week 
        AND t.time_slot = NEW.time_slot 
        AND t.academic_year = NEW.academic_year
        AND t.id != COALESCE(NEW.id, 0)
        AND t.is_active = TRUE;
    END IF;

    -- Check for room double booking
    IF EXISTS (
        SELECT 1 FROM timetable 
        WHERE room_id = NEW.room_id 
        AND day_of_week = NEW.day_of_week 
        AND time_slot = NEW.time_slot 
        AND academic_year = NEW.academic_year
        AND id != COALESCE(NEW.id, 0)
        AND is_active = TRUE
    ) THEN
        INSERT INTO conflicts (conflict_type, description, severity, timetable_id_1, timetable_id_2)
        SELECT 'room_double_booking', 
               'Room is assigned to multiple classes at the same time',
               'high',
               NEW.id,
               t.id
        FROM timetable t 
        WHERE t.room_id = NEW.room_id 
        AND t.day_of_week = NEW.day_of_week 
        AND t.time_slot = NEW.time_slot 
        AND t.academic_year = NEW.academic_year
        AND t.id != COALESCE(NEW.id, 0)
        AND t.is_active = TRUE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for conflict detection
CREATE TRIGGER trigger_detect_conflicts
    AFTER INSERT OR UPDATE ON timetable
    FOR EACH ROW
    EXECUTE FUNCTION detect_timetable_conflicts();

-- Function for audit logging
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO audit_log (user_id, action, table_name, record_id, old_values)
        VALUES (
            COALESCE(current_setting('app.current_user_id', true)::INTEGER, NULL),
            TG_OP,
            TG_TABLE_NAME,
            OLD.id,
            to_jsonb(OLD)
        );
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values)
        VALUES (
            COALESCE(current_setting('app.current_user_id', true)::INTEGER, NULL),
            TG_OP,
            TG_TABLE_NAME,
            NEW.id,
            to_jsonb(OLD),
            to_jsonb(NEW)
        );
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (user_id, action, table_name, record_id, new_values)
        VALUES (
            COALESCE(current_setting('app.current_user_id', true)::INTEGER, NULL),
            TG_OP,
            TG_TABLE_NAME,
            NEW.id,
            to_jsonb(NEW)
        );
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION validate_batch_timetable(
    p_batch VARCHAR,
    p_academic_year VARCHAR DEFAULT '2024-25'
)
RETURNS TABLE(
    validation_type VARCHAR,
    is_valid BOOLEAN,
    conflict_count INTEGER,
    details JSONB
) AS $$
BEGIN
    -- Check faculty conflicts
    RETURN QUERY
    SELECT 
        'faculty_conflicts'::VARCHAR,
        COUNT(*) = 0,
        COUNT(*)::INTEGER,
        jsonb_agg(
            jsonb_build_object(
                'faculty', faculty_name,
                'day', day_of_week,
                'time', time_slot,
                'batches', affected_batches
            )
        )
    FROM v_timetable_conflicts
    WHERE conflict_type = 'Faculty Double Booking'
    AND academic_year = p_academic_year
    AND affected_batches LIKE '%' || p_batch || '%';
    
    -- Check room conflicts
    RETURN QUERY
    SELECT 
        'room_conflicts'::VARCHAR,
        COUNT(*) = 0,
        COUNT(*)::INTEGER,
        jsonb_agg(
            jsonb_build_object(
                'room', resource_name,
                'day', day_of_week,
                'time', time_slot,
                'batches', affected_batches
            )
        )
    FROM v_timetable_conflicts
    WHERE conflict_type = 'Room Double Booking'
    AND academic_year = p_academic_year
    AND affected_batches LIKE '%' || p_batch || '%';
    
    -- Check lab room mismatches
    RETURN QUERY
    SELECT 
        'lab_room_mismatch'::VARCHAR,
        COUNT(*) = 0,
        COUNT(*)::INTEGER,
        jsonb_agg(
            jsonb_build_object(
                'subject', conflicting_subjects,
                'room', resource_name,
                'day', day_of_week,
                'time', time_slot
            )
        )
    FROM v_timetable_conflicts
    WHERE conflict_type = 'Lab Room Type Mismatch'
    AND affected_batches = p_batch
    AND academic_year = p_academic_year;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION analyze_workload_balance(
    p_batch VARCHAR DEFAULT NULL,
    p_academic_year VARCHAR DEFAULT '2024-25'
)
RETURNS TABLE(
    analysis_type VARCHAR,
    resource_name VARCHAR,
    current_load NUMERIC,
    max_capacity NUMERIC,
    utilization_percentage NUMERIC,
    status VARCHAR,
    recommendation TEXT
) AS $$
BEGIN
    -- Faculty workload analysis
    RETURN QUERY
    SELECT 
        'faculty'::VARCHAR,
        f.name,
        COUNT(t.id)::NUMERIC,
        f.max_hours_per_week::NUMERIC,
        ROUND((COUNT(t.id) * 100.0 / f.max_hours_per_week), 2),
        CASE 
            WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 100 THEN 'overloaded'
            WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 90 THEN 'very_high'
            WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 70 THEN 'high'
            WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 40 THEN 'optimal'
            ELSE 'underutilized'
        END,
        CASE 
            WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 100 THEN 
                'Reduce teaching load or redistribute classes'
            WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week < 40 THEN 
                'Can take additional classes'
            ELSE 'Workload is balanced'
        END
    FROM faculty f
    LEFT JOIN timetable t ON f.id = t.faculty_id 
        AND t.is_active = TRUE
        AND t.academic_year = p_academic_year
        AND (p_batch IS NULL OR t.batch = p_batch)
    WHERE f.is_active = TRUE
    GROUP BY f.id, f.name, f.max_hours_per_week
    HAVING COUNT(t.id) > 0;
    
    -- Room utilization analysis
    RETURN QUERY
    SELECT 
        'room'::VARCHAR,
        r.name || ' (' || r.type || ')',
        COUNT(t.id)::NUMERIC,
        30::NUMERIC, -- 30 slots per week (5 days × 6 slots)
        ROUND((COUNT(t.id) * 100.0 / 30), 2),
        CASE 
            WHEN COUNT(t.id) * 100.0 / 30 > 80 THEN 'high_usage'
            WHEN COUNT(t.id) * 100.0 / 30 > 50 THEN 'medium_usage'
            ELSE 'low_usage'
        END,
        CASE 
            WHEN COUNT(t.id) * 100.0 / 30 > 80 THEN 
                'Consider adding more rooms or redistributing classes'
            WHEN COUNT(t.id) * 100.0 / 30 < 30 THEN 
                'Room is underutilized, can accommodate more classes'
            ELSE 'Room utilization is optimal'
        END
    FROM rooms r
    LEFT JOIN timetable t ON r.id = t.room_id 
        AND t.is_active = TRUE
        AND t.academic_year = p_academic_year
        AND (p_batch IS NULL OR t.batch = p_batch)
    WHERE r.is_active = TRUE
    GROUP BY r.id, r.name, r.type
    HAVING COUNT(t.id) > 0;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION analyze_elective_alignment(
    p_academic_year VARCHAR DEFAULT '2024-25'
)
RETURNS TABLE(
    elective_name VARCHAR,
    total_batches INTEGER,
    unique_time_slots INTEGER,
    aligned BOOLEAN,
    time_slot_distribution JSONB,
    recommendation TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.name,
        COUNT(DISTINCT t.batch)::INTEGER,
        COUNT(DISTINCT (t.day_of_week || ' ' || t.time_slot))::INTEGER,
        COUNT(DISTINCT (t.day_of_week || ' ' || t.time_slot)) = 1,
        jsonb_agg(
            DISTINCT jsonb_build_object(
                'batch', t.batch,
                'day', t.day_of_week,
                'time', t.time_slot
            )
        ),
        CASE 
            WHEN COUNT(DISTINCT (t.day_of_week || ' ' || t.time_slot)) = 1 THEN
                'Elective is properly aligned across batches'
            ELSE
                'Consider aligning ' || s.name || ' at same time across all batches for resource sharing'
        END
    FROM subjects s
    JOIN timetable t ON s.id = t.subject_id
    WHERE s.name ILIKE '%elective%'
    AND t.academic_year = p_academic_year
    AND t.is_active = TRUE
    GROUP BY s.id, s.name
    HAVING COUNT(DISTINCT t.batch) > 1;
END;
$$ LANGUAGE plpgsql;

-- Create audit triggers for important tables
CREATE TRIGGER audit_users AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
CREATE TRIGGER audit_timetable AFTER INSERT OR UPDATE OR DELETE ON timetable FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
CREATE TRIGGER audit_swap_requests AFTER INSERT OR UPDATE OR DELETE ON swap_requests FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
CREATE TRIGGER audit_leave_requests AFTER INSERT OR UPDATE OR DELETE ON leave_requests FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

-- ==================== VIEWS ====================

-- View for timetable with all details
CREATE OR REPLACE VIEW v_timetable_details AS
SELECT 
    t.id,
    t.batch,
    t.day_of_week,
    t.time_slot,
    t.duration_minutes,
    t.session_type,
    t.semester,
    t.academic_year,
    s.name AS subject_name,
    s.code AS subject_code,
    s.type AS subject_type,
    s.credits,
    f.name AS faculty_name,
    f.department AS faculty_department,
    r.name AS room_name,
    r.type AS room_type,
    r.capacity AS room_capacity,
    r.building,
    r.floor,
    t.is_active,
    t.created_at,
    t.updated_at
FROM timetable t
JOIN subjects s ON t.subject_id = s.id
JOIN faculty f ON t.faculty_id = f.id
JOIN rooms r ON t.room_id = r.id;

-- View for faculty workload summary
CREATE OR REPLACE VIEW v_faculty_workload AS
SELECT 
    f.id,
    f.name,
    f.department,
    f.max_hours_per_week,
    COUNT(t.id) AS weekly_classes,
    SUM(t.duration_minutes) / 60.0 AS total_weekly_hours,
    ROUND((SUM(t.duration_minutes) / 60.0) / f.max_hours_per_week * 100, 2) AS workload_percentage,
    CASE 
        WHEN SUM(t.duration_minutes) / 60.0 > f.max_hours_per_week THEN 'Overloaded'
        WHEN SUM(t.duration_minutes) / 60.0 > f.max_hours_per_week * 0.8 THEN 'High Load'
        WHEN SUM(t.duration_minutes) / 60.0 > f.max_hours_per_week * 0.5 THEN 'Optimal'
        ELSE 'Under-utilized'
    END AS load_status
FROM faculty f
LEFT JOIN timetable t ON f.id = t.faculty_id AND t.is_active = TRUE
WHERE f.is_active = TRUE
GROUP BY f.id, f.name, f.department, f.max_hours_per_week;

-- View for room utilization summary
CREATE OR REPLACE VIEW v_resource_utilization_analysis AS
SELECT 
    'Room' as resource_type,
    r.name as resource_name,
    r.department,
    r.type as resource_subtype,
    COUNT(t.id) as total_allocations,
    ROUND(COUNT(t.id) * 100.0 / 30, 2) as utilization_percentage,
    CASE 
        WHEN COUNT(t.id) * 100.0 / 30 > 80 THEN 'High'
        WHEN COUNT(t.id) * 100.0 / 30 > 50 THEN 'Medium'
        ELSE 'Low'
    END as utilization_level
FROM rooms r
LEFT JOIN timetable t ON r.id = t.room_id AND t.is_active = TRUE
WHERE r.is_active = TRUE
GROUP BY r.id, r.name, r.department, r.type

UNION ALL

SELECT 
    'Faculty' as resource_type,
    f.name as resource_name,
    f.department,
    f.designation as resource_subtype,
    COUNT(t.id) as total_allocations,
    ROUND(COUNT(t.id) * 100.0 / f.max_hours_per_week, 2) as utilization_percentage,
    CASE 
        WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 100 THEN 'Overloaded'
        WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 90 THEN 'Very High'
        WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 70 THEN 'High'
        WHEN COUNT(t.id) * 100.0 / f.max_hours_per_week > 40 THEN 'Medium'
        ELSE 'Low'
    END as utilization_level
FROM faculty f
LEFT JOIN timetable t ON f.id = t.faculty_id AND t.is_active = TRUE
WHERE f.is_active = TRUE
GROUP BY f.id, f.name, f.department, f.max_hours_per_week, f.designation;

-- ==================== INITIAL DATA ====================

-- Insert default users
INSERT INTO users (username, password, email, role) VALUES 
('admin', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@university.edu', 'admin'), -- password: password
('faculty1', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'faculty1@university.edu', 'faculty'),
('student1', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'student1@university.edu', 'student');

-- Insert sample departments
INSERT INTO faculty (name, email, department, designation, hire_date) VALUES 
('Dr. John Smith', 'smith@university.edu', 'Computer Science', 'Professor', '2020-01-15'),
('Prof. Sarah Johnson', 'johnson@university.edu', 'Mathematics', 'Associate Professor', '2018-08-20'),
('Dr. Michael Williams', 'williams@university.edu', 'Physics', 'Assistant Professor', '2021-03-10'),
('Dr. Emily Brown', 'brown@university.edu', 'Computer Science', 'Professor', '2017-05-12'),
('Prof. David Davis', 'davis@university.edu', 'Mathematics', 'Professor', '2019-09-08');

-- Insert sample subjects
INSERT INTO subjects (name, code, department, semester, credits, type, description) VALUES 
('Data Structures', 'CS301', 'Computer Science', 3, 4, 'Theory', 'Introduction to data structures and algorithms'),
('Database Management Systems', 'CS401', 'Computer Science', 4, 4, 'Theory', 'Fundamentals of database design and management'),
('Programming Lab', 'CS302L', 'Computer Science', 3, 2, 'Practical', 'Hands-on programming exercises'),
('Calculus I', 'MATH201', 'Mathematics', 2, 3, 'Theory', 'Differential and integral calculus'),
('Linear Algebra', 'MATH301', 'Mathematics', 3, 3, 'Theory', 'Matrices, vectors, and linear transformations'),
('Physics Lab', 'PHY101L', 'Physics', 1, 2, 'Practical', 'Basic physics laboratory experiments');

-- Insert sample rooms
INSERT INTO rooms (name, type, capacity, department, building, floor, facilities) VALUES 
('Room 101', 'Classroom', 50, 'Computer Science', 'Block A', 1, ARRAY['Projector', 'Whiteboard', 'AC']),
('Lab 201', 'Lab', 30, 'Computer Science', 'Block A', 2, ARRAY['Computers', 'Projector', 'AC']),
('Room 301', 'Classroom', 60, 'Mathematics', 'Block B', 3, ARRAY['Projector', 'Whiteboard']),
('Auditorium A', 'Auditorium', 200, 'General', 'Main Building', 1, ARRAY['Audio System', 'Projector', 'Stage']),
('Lab 102', 'Lab', 25, 'Physics', 'Block C', 1, ARRAY['Equipment', 'Safety Gear']);

-- Insert sample students
INSERT INTO students (name, email, roll_number, batch, semester, department) VALUES 
('Alice Brown', 'alice@student.edu', 'CS2023001', 'CS2023', 3, 'Computer Science'),
('Bob Wilson', 'bob@student.edu', 'CS2023002', 'CS2023', 3, 'Computer Science'),
('Carol Davis', 'carol@student.edu', 'MATH2023001', 'MATH2023', 3, 'Mathematics'),
('David Johnson', 'david@student.edu', 'CS2023003', 'CS2023', 3, 'Computer Science'),
('Eva Martinez', 'eva@student.edu', 'PHY2023001', 'PHY2023', 3, 'Physics');

-- Link faculty with subjects
INSERT INTO faculty_subjects (faculty_id, subject_id, subject_name, is_primary) VALUES 
(1, 1, 'Data Structures', TRUE),
(1, 2, 'Database Management Systems', TRUE),
(1, 3, 'Programming Lab', TRUE),
(2, 4, 'Calculus I', TRUE),
(2, 5, 'Linear Algebra', TRUE),
(3, 6, 'Physics Lab', TRUE);

-- Insert current academic calendar
-- INSERT INTO academic_calendar (academic_year, semester, start_date, end_date, exam_start_date, exam_end_date, holidays) VALUES 
-- ('2023-24', 1, '2023-07-01', '2023-11-30', '2023-11-15', '2023-11-30', 
--  '[{"date": "2023-08-15", "description": "Independence Day"}, {"date": "2023-10-02", "description": "Gandhi Jayanti"}]'::jsonb),
-- ('2023-24', 2, '2024-01-01', '2024-05-31', '2024-05-15', '2024-05-31',
--  '[{"date": "2024-01-26", "description": "Republic Day"}, {"date": "2024-03-08", "description": "Holi"}]'::jsonb);

-- Sample timetable entries
INSERT INTO timetable (batch, subject_id, faculty_id, room_id, day_of_week, time_slot, session_type, semester, academic_year) VALUES 
('CS2023', 1, 1, 1, 'Monday', '09:00-10:00', 'Lecture', 3, '2023-24'),
('CS2023', 3, 1, 2, 'Monday', '14:00-16:00', 'Lab', 3, '2023-24'),
('CS2023', 2, 1, 1, 'Tuesday', '10:00-11:00', 'Lecture', 3, '2023-24'),
('MATH2023', 4, 2, 3, 'Monday', '11:00-12:00', 'Lecture', 3, '2023-24'),
('MATH2023', 5, 2, 3, 'Tuesday', '09:00-10:00', 'Lecture', 3, '2023-24');

-- ==================== STORED PROCEDURES ====================

-- Procedure to generate automatic timetable
CREATE OR REPLACE FUNCTION generate_timetable(
    p_batch VARCHAR,
    p_semester INTEGER,
    p_academic_year VARCHAR
) RETURNS TABLE(
    status VARCHAR,
    classes_generated INTEGER,
    conflicts_detected INTEGER
) AS $$
DECLARE
    subject_rec RECORD;
    faculty_rec RECORD;
    room_rec RECORD;
    time_slots TEXT[] := ARRAY['09:00-10:00', '10:00-11:00', '11:00-12:00', '14:00-15:00', '15:00-16:00', '16:00-17:00'];
    days TEXT[] := ARRAY['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
    classes_count INTEGER := 0;
    conflicts_count INTEGER := 0;
BEGIN
    -- Clear existing timetable for the batch
    DELETE FROM timetable WHERE batch = p_batch AND semester = p_semester AND academic_year = p_academic_year;
    
    -- Loop through subjects for the semester
    FOR subject_rec IN 
        SELECT * FROM subjects 
        WHERE semester = p_semester AND is_active = TRUE
    LOOP
        -- Find available faculty for the subject
        FOR faculty_rec IN
            SELECT f.* FROM faculty f
            JOIN faculty_subjects fs ON f.id = fs.faculty_id
            WHERE fs.subject_id = subject_rec.id AND f.is_active = TRUE
            LIMIT 1
        LOOP
            -- Find available room
            FOR room_rec IN
                SELECT * FROM rooms 
                WHERE (department = subject_rec.department OR department = 'General')
                AND type = CASE WHEN subject_rec.type = 'Practical' THEN 'Lab' ELSE 'Classroom' END
                AND is_active = TRUE
                LIMIT 1
            LOOP
                -- Try to schedule the class
                FOR i IN 1..array_length(days, 1) LOOP
                    FOR j IN 1..array_length(time_slots, 1) LOOP
                        -- Check for conflicts
                        IF NOT EXISTS (
                            SELECT 1 FROM timetable 
                            WHERE (faculty_id = faculty_rec.id OR room_id = room_rec.id)
                            AND day_of_week = days[i]
                            AND time_slot = time_slots[j]
                            AND academic_year = p_academic_year
                        ) THEN
                            -- Insert the class
                            INSERT INTO timetable (
                                batch, subject_id, faculty_id, room_id, 
                                day_of_week, time_slot, session_type, 
                                semester, academic_year
                            ) VALUES (
                                p_batch, subject_rec.id, faculty_rec.id, room_rec.id,
                                days[i], time_slots[j], 
                                CASE WHEN subject_rec.type = 'Practical' THEN 'Lab' ELSE 'Lecture' END,
                                p_semester, p_academic_year
                            );
                            
                            classes_count := classes_count + 1;
                            EXIT; -- Exit time slot loop
                        END IF;
                    END LOOP;
                    
                    IF classes_count > 0 THEN
                        EXIT; -- Exit day loop if class was scheduled
                    END IF;
                END LOOP;
            END LOOP;
        END LOOP;
    END LOOP;
    
    -- Count conflicts
    SELECT COUNT(*) INTO conflicts_count FROM conflicts WHERE status = 'active';
    
    RETURN QUERY SELECT 'success'::VARCHAR, classes_count, conflicts_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get analytics data
CREATE OR REPLACE FUNCTION get_dashboard_analytics()
RETURNS TABLE(
    total_faculty INTEGER,
    total_students INTEGER,
    total_rooms INTEGER,
    total_subjects INTEGER,
    active_timetables INTEGER,
    pending_swap_requests INTEGER,
    pending_leave_requests INTEGER,
    room_utilization NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (SELECT COUNT(*)::INTEGER FROM faculty WHERE is_active = TRUE),
        (SELECT COUNT(*)::INTEGER FROM students WHERE is_active = TRUE),
        (SELECT COUNT(*)::INTEGER FROM rooms WHERE is_active = TRUE),
        (SELECT COUNT(*)::INTEGER FROM subjects WHERE is_active = TRUE),
        (SELECT COUNT(*)::INTEGER FROM timetable WHERE is_active = TRUE),
        (SELECT COUNT(*)::INTEGER FROM swap_requests WHERE status = 'pending'),
        (SELECT COUNT(*)::INTEGER FROM leave_requests WHERE status = 'pending'),
        (SELECT AVG(utilization_percentage) FROM v_room_utilization);
END;
$$ LANGUAGE plpgsql;
-- event_date DATE,
    -- is_active BOOLEAN

-- ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS affected_classes JSONB;
-- ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS auto_rescheduled BOOLEAN DEFAULT FALSE;
-- ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS reschedule_details JSONB;

-- CREATE TABLE IF NOT EXISTS substitute_faculty (
--     id SERIAL PRIMARY KEY,
--     faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
--     substitute_faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
--     subjects TEXT[], -- Subjects the substitute can handle
--     priority INTEGER DEFAULT 1, -- 1=highest, 5=lowest
--     availability JSONB, -- JSON with day/time availability
--     is_active BOOLEAN DEFAULT TRUE,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     UNIQUE(faculty_id, substitute_faculty_id)
-- );

-- CREATE TABLE IF NOT EXISTS timetable_history (
--     id SERIAL PRIMARY KEY,
--     original_timetable_id INTEGER REFERENCES timetable(id),
--     batch VARCHAR(20) NOT NULL,
--     subject_id INTEGER REFERENCES subjects(id),
--     faculty_id INTEGER REFERENCES faculty(id),
--     room_id INTEGER REFERENCES rooms(id),
--     day_of_week VARCHAR(10) NOT NULL,
--     time_slot VARCHAR(20) NOT NULL,
--     change_type VARCHAR(20) NOT NULL CHECK (change_type IN ('created', 'modified', 'cancelled', 'rescheduled')),
--     change_reason VARCHAR(50), -- 'faculty_leave', 'room_unavailable', 'manual', etc.
--     changed_by INTEGER REFERENCES users(id),
--     change_details JSONB,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );

-- CREATE TABLE IF NOT EXISTS reschedule_queue (
--     id SERIAL PRIMARY KEY,
--     priority INTEGER DEFAULT 5, -- 1=highest, 10=lowest
--     timetable_id INTEGER REFERENCES timetable(id) ON DELETE CASCADE,
--     reason VARCHAR(50) NOT NULL,
--     original_faculty_id INTEGER REFERENCES faculty(id),
--     original_room_id INTEGER REFERENCES rooms(id),
--     constraints JSONB, -- Scheduling constraints
--     status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
--     attempts INTEGER DEFAULT 0,
--     max_attempts INTEGER DEFAULT 3,
--     error_message TEXT,
--     processed_at TIMESTAMP,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );

-- CREATE TABLE IF NOT EXISTS real_time_notifications (
--     id SERIAL PRIMARY KEY,
--     notification_type VARCHAR(30) NOT NULL,
--     affected_users INTEGER[], -- Array of user IDs
--     title VARCHAR(200) NOT NULL,
--     message TEXT NOT NULL,
--     data JSONB, -- Additional data for frontend
--     priority VARCHAR(10) DEFAULT 'normal',
--     sent BOOLEAN DEFAULT FALSE,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );

-- CREATE TABLE IF NOT EXISTS faculty_availability (
--     id SERIAL PRIMARY KEY,
--     faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
--     day_of_week VARCHAR(10) NOT NULL,
--     start_time TIME NOT NULL,
--     end_time TIME NOT NULL,
--     availability_type VARCHAR(20) DEFAULT 'available' CHECK (availability_type IN ('available', 'preferred', 'unavailable')),
--     reason TEXT,
--     effective_date DATE,
--     expiry_date DATE,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     UNIQUE(faculty_id, day_of_week, start_time, end_time, effective_date)
-- );

-- -- 3. Add indexes for better performance
-- CREATE INDEX IF NOT EXISTS idx_timetable_faculty_day_time ON timetable(faculty_id, day_of_week, time_slot);
-- CREATE INDEX IF NOT EXISTS idx_timetable_room_day_time ON timetable(room_id, day_of_week, time_slot);
-- CREATE INDEX IF NOT EXISTS idx_reschedule_queue_priority ON reschedule_queue(priority, status);
-- CREATE INDEX IF NOT EXISTS idx_leave_requests_dates ON leave_requests(start_date, end_date, status);
-- CREATE INDEX IF NOT EXISTS idx_faculty_availability_lookup ON faculty_availability(faculty_id, day_of_week, availability_type);

-- 4. Add the automatic leave handling function
CREATE OR REPLACE FUNCTION handle_faculty_leave(
    p_faculty_id INTEGER,
    p_start_date DATE,
    p_end_date DATE,
    p_leave_request_id INTEGER
) RETURNS TABLE(
    affected_classes_count INTEGER,
    rescheduled_count INTEGER,
    substitute_assigned_count INTEGER,
    cancelled_count INTEGER
) AS $$
DECLARE
    class_rec RECORD;
    substitute_rec RECORD;
    affected_count INTEGER := 0;
    rescheduled_count INTEGER := 0;
    substitute_count INTEGER := 0;
    cancelled_count INTEGER := 0;
    affected_classes JSONB := '[]'::JSONB;
    leave_days TEXT[];
BEGIN
    -- Generate array of affected days
    SELECT ARRAY(
        SELECT to_char(generate_series(p_start_date, p_end_date, '1 day'::interval), 'Day')
    ) INTO leave_days;

    -- Clean up day names (remove extra spaces)
    FOR i IN 1..array_length(leave_days, 1) LOOP
        leave_days[i] := TRIM(leave_days[i]);
    END LOOP;

    -- Find all affected classes
    FOR class_rec IN 
        SELECT t.*, s.name as subject_name, r.name as room_name
        FROM timetable t
        JOIN subjects s ON t.subject_id = s.id
        JOIN rooms r ON t.room_id = r.id
        WHERE t.faculty_id = p_faculty_id 
        AND t.is_active = TRUE
        AND t.day_of_week = ANY(leave_days)
    LOOP
        affected_count := affected_count + 1;
        
        -- Add to affected classes JSON
        affected_classes := affected_classes || jsonb_build_object(
            'timetable_id', class_rec.id,
            'subject', class_rec.subject_name,
            'day', class_rec.day_of_week,
            'time', class_rec.time_slot,
            'room', class_rec.room_name,
            'batch', class_rec.batch
        );

        -- Try to find a substitute faculty
        SELECT sf.substitute_faculty_id, f.name
        INTO substitute_rec
        FROM substitute_faculty sf
        JOIN faculty f ON sf.substitute_faculty_id = f.id
        WHERE sf.faculty_id = p_faculty_id 
        AND f.is_active = TRUE
        AND class_rec.subject_id = ANY(
            SELECT s.id FROM subjects s 
            WHERE s.name = ANY(sf.subjects)
        )
        -- Check substitute availability
        AND NOT EXISTS (
            SELECT 1 FROM timetable t2 
            WHERE t2.faculty_id = sf.substitute_faculty_id 
            AND t2.day_of_week = class_rec.day_of_week 
            AND t2.time_slot = class_rec.time_slot
            AND t2.is_active = TRUE
        )
        ORDER BY sf.priority
        LIMIT 1;

        IF substitute_rec.substitute_faculty_id IS NOT NULL THEN
            -- Assign substitute
            UPDATE timetable 
            SET faculty_id = substitute_rec.substitute_faculty_id
            WHERE id = class_rec.id;
            
            substitute_count := substitute_count + 1;
        ELSE
            -- Add to reschedule queue for manual handling
            INSERT INTO reschedule_queue (
                priority, timetable_id, reason, original_faculty_id, 
                original_room_id, constraints
            ) VALUES (
                1, class_rec.id, 'faculty_leave', p_faculty_id, 
                class_rec.room_id,
                jsonb_build_object(
                    'leave_start_date', p_start_date,
                    'leave_end_date', p_end_date,
                    'subject_id', class_rec.subject_id
                )
            );
            
            -- Temporarily cancel the class
            UPDATE timetable SET is_active = FALSE WHERE id = class_rec.id;
            cancelled_count := cancelled_count + 1;
        END IF;
    END LOOP;

    -- Update leave request with affected classes info
    UPDATE leave_requests 
    SET affected_classes = affected_classes,
        auto_rescheduled = CASE WHEN (rescheduled_count + substitute_count) > 0 THEN TRUE ELSE FALSE END,
        reschedule_details = jsonb_build_object(
            'total_affected', affected_count,
            'substitutes_assigned', substitute_count,
            'rescheduled', rescheduled_count,
            'cancelled', cancelled_count,
            'processed_at', CURRENT_TIMESTAMP
        )
    WHERE id = p_leave_request_id;

    RETURN QUERY SELECT affected_count, rescheduled_count, substitute_count, cancelled_count;
END;
$$ LANGUAGE plpgsql;

-- 5. Add trigger to automatically handle leave approval
CREATE OR REPLACE FUNCTION trigger_auto_reschedule()
RETURNS TRIGGER AS $$
BEGIN
    -- Only trigger when leave is approved
    IF NEW.status = 'approved' AND OLD.status != 'approved' THEN
        -- Call the automatic rescheduling function
        PERFORM handle_faculty_leave(
            NEW.faculty_id,
            NEW.start_date,
            NEW.end_date,
            NEW.id
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_leave_approval
    AFTER UPDATE ON leave_requests
    FOR EACH ROW
    EXECUTE FUNCTION trigger_auto_reschedule();


CREATE OR REPLACE FUNCTION check_elective_alignment()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if this is an elective subject
    IF EXISTS (
        SELECT 1 FROM subjects 
        WHERE id = NEW.subject_id 
        AND name ILIKE '%elective%'
    ) THEN
        -- Check if other batches have same elective at different times
        IF EXISTS (
            SELECT 1 FROM timetable t
            JOIN subjects s ON t.subject_id = s.id
            WHERE s.name ILIKE '%elective%'
            AND t.day_of_week = NEW.day_of_week
            AND t.time_slot != NEW.time_slot
            AND t.academic_year = NEW.academic_year
            AND t.is_active = TRUE
            AND t.batch != NEW.batch
        ) THEN
            RAISE WARNING 'ELECTIVE_ALIGNMENT: Elective subjects should be aligned across batches at same time for resource optimization';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for elective alignment
-- DROP TRIGGER IF EXISTS trigger_check_elective_alignment ON timetable;
-- CREATE TRIGGER trigger_check_elective_alignment
--     BEFORE INSERT OR UPDATE ON timetable
--     FOR EACH ROW
--     EXECUTE FUNCTION check_elective_alignment();

-- 6. Insert sample substitute faculty data
INSERT INTO substitute_faculty (faculty_id, substitute_faculty_id, subjects, priority) VALUES 
(1, 4, ARRAY['Data Structures', 'Database Management Systems'], 1), -- Dr. Emily Brown can substitute for Dr. John Smith
(2, 5, ARRAY['Calculus I', 'Linear Algebra'], 1) -- Prof. David Davis can substitute for Prof. Sarah Johnson
ON CONFLICT DO NOTHING;

-- 7. Create view for real-time dashboard
CREATE OR REPLACE VIEW v_real_time_dashboard AS
SELECT 
    'leave_requests' as metric_type,
    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_count,
    COUNT(CASE WHEN status = 'approved' AND start_date <= CURRENT_DATE AND end_date >= CURRENT_DATE THEN 1 END) as active_count,
    COUNT(*) as total_count
FROM leave_requests
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'

UNION ALL

SELECT 
    'reschedule_queue' as metric_type,
    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_count,
    COUNT(CASE WHEN status = 'processing' THEN 1 END) as active_count,
    COUNT(*) as total_count
FROM reschedule_queue

UNION ALL

SELECT 
    'conflicts' as metric_type,
    COUNT(CASE WHEN status = 'active' THEN 1 END) as pending_count,
    0 as active_count,
    COUNT(*) as total_count
FROM conflicts;



UPDATE faculty SET email = 'faculty@university.edu' WHERE name = 'Dr. John Smith';
UPDATE faculty SET email = 'faculty2@university.edu' WHERE name = 'Prof. Sarah Johnson';
UPDATE faculty SET email = 'faculty3@university.edu' WHERE name = 'Dr. Michael Williams';
UPDATE faculty SET email = 'jayesh@university.edu' WHERE name = 'Jayesh';

INSERT INTO users (username, password, email, role) VALUES 
('johnsmith', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'faculty1@university.edu', 'faculty'),
('sarahjohnson', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'faculty2@university.edu', 'faculty'),
('michaelwilliams', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'faculty3@university.edu', 'faculty')
ON CONFLICT (email) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_leave_requests_faculty ON leave_requests(faculty_id);
CREATE INDEX IF NOT EXISTS idx_leave_requests_status ON leave_requests(status);
CREATE INDEX IF NOT EXISTS idx_leave_requests_dates ON leave_requests(start_date, end_date);

INSERT INTO leave_requests (faculty_id, leave_type, start_date, end_date, reason, status) VALUES
(1, 'Casual', '2024-01-15', '2024-01-17', 'Family function', 'pending'),
(2, 'Conference', '2024-02-20', '2024-02-22', 'Attending IEEE Conference', 'approved'),
(1, 'Sick', '2024-01-10', '2024-01-12', 'Medical treatment', 'rejected');


SELECT 
    'Batch Uniqueness Constraint' as constraint_name,
    EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_timetable_batch_slot'
    ) as is_active;

-- Query to verify conflict detection view
-- SELECT 
--     conflict_type,
--     COUNT(*) as total_conflicts
-- FROM v_timetable_conflicts
-- GROUP BY conflict_type;

-- -- Query to check workload balance
-- SELECT * FROM analyze_workload_balance(NULL, '2024-25')
-- ORDER BY utilization_percentage DESC;

-- -- Query to check elective alignment
-- SELECT * FROM analyze_elective_alignment('2024-25');


SELECT DISTINCT 
    CASE 
        WHEN affected_batches LIKE '%&%' THEN 
            TRIM(SPLIT_PART(affected_batches, '&', 1))
        ELSE affected_batches
    END as batch,
    COUNT(*) as conflict_count
FROM v_timetable_conflicts
WHERE academic_year = '2024-25'
GROUP BY batch
ORDER BY conflict_count DESC;

-- Query to find overloaded faculty
-- SELECT 
--     resource_name as faculty_name,
--     utilization_percentage,
--     CASE 
--         WHEN utilization_percentage > 100 THEN 'CRITICAL'
--         WHEN utilization_percentage > 90 THEN 'HIGH'
--         ELSE 'NORMAL'
--     END as alert_level
-- FROM v_resource_utilization_analysis
-- WHERE resource_type = 'Faculty'
-- AND utilization_percentage > 90
-- ORDER BY utilization_percentage DESC;

-- Query to find underutilized rooms
-- SELECT 
--     resource_name as room_name,
--     resource_subtype as room_type,
--     utilization_percentage,
--     30 - total_allocations as available_slots
-- FROM v_resource_utilization_analysis
-- WHERE resource_type = 'Room'
-- AND utilization_percentage < 50
-- ORDER BY utilization_percentage ASC;

-- Check if unique constraint exists on subjects.code
SELECT constraint_name, constraint_type 
FROM information_schema.table_constraints 
WHERE table_name = 'subjects' AND constraint_type = 'UNIQUE';

-- If it doesn't exist, add it:
ALTER TABLE subjects ADD CONSTRAINT subjects_code_unique UNIQUE (code);


-- ==================== DATABASE FIXES FOR LEAVE & SWAP REQUESTS ====================

-- 1. Disable the automatic trigger temporarily (it might be interfering)
DROP TRIGGER IF EXISTS trigger_leave_approval ON leave_requests;

-- 2. Add missing column to leave_requests if needed
ALTER TABLE leave_requests 
ADD COLUMN IF NOT EXISTS affected_classes JSONB;

-- 3. Ensure reschedule_queue table exists with correct structure
CREATE TABLE IF NOT EXISTS reschedule_queue (
    id SERIAL PRIMARY KEY,
    priority INTEGER DEFAULT 5,
    timetable_id INTEGER REFERENCES timetable(id) ON DELETE CASCADE,
    reason VARCHAR(50) NOT NULL,
    original_faculty_id INTEGER REFERENCES faculty(id),
    original_room_id INTEGER REFERENCES rooms(id),
    constraints JSONB,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    error_message TEXT,
    processed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Ensure timetable_history table exists
CREATE TABLE IF NOT EXISTS timetable_history (
    id SERIAL PRIMARY KEY,
    original_timetable_id INTEGER REFERENCES timetable(id),
    batch VARCHAR(20) NOT NULL,
    subject_id INTEGER REFERENCES subjects(id),
    faculty_id INTEGER REFERENCES faculty(id),
    room_id INTEGER REFERENCES rooms(id),
    day_of_week VARCHAR(10) NOT NULL,
    time_slot VARCHAR(20) NOT NULL,
    change_type VARCHAR(20) NOT NULL CHECK (change_type IN ('created', 'modified', 'cancelled', 'rescheduled')),
    change_reason VARCHAR(50),
    changed_by INTEGER REFERENCES users(id),
    change_details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_leave_requests_faculty_status 
ON leave_requests(faculty_id, status);

CREATE INDEX IF NOT EXISTS idx_leave_requests_dates_active 
ON leave_requests(start_date, end_date) 
WHERE status = 'approved';

CREATE INDEX IF NOT EXISTS idx_swap_requests_status 
ON swap_requests(status);

CREATE INDEX IF NOT EXISTS idx_reschedule_queue_status 
ON reschedule_queue(status, priority);

CREATE INDEX IF NOT EXISTS idx_timetable_history_created 
ON timetable_history(created_at DESC);

-- 6. Add section column to timetable_history if missing
ALTER TABLE timetable_history 
ADD COLUMN IF NOT EXISTS section VARCHAR(1);

-- 7. Fix swap_requests table to ensure all needed columns exist
ALTER TABLE swap_requests 
ADD COLUMN IF NOT EXISTS original_time_slot VARCHAR(20);

-- 8. Create helpful views for monitoring

-- View for pending actions
CREATE OR REPLACE VIEW v_pending_actions AS
SELECT 
    'leave_request' as action_type,
    lr.id,
    f.name as faculty_name,
    lr.start_date,
    lr.end_date,
    lr.created_at,
    lr.reason as description
FROM leave_requests lr
JOIN faculty f ON lr.faculty_id = f.id
WHERE lr.status = 'pending'

UNION ALL

SELECT 
    'swap_request' as action_type,
    sr.id,
    rf.name as faculty_name,
    NULL as start_date,
    NULL as end_date,
    sr.created_at,
    sr.reason as description
FROM swap_requests sr
JOIN faculty rf ON sr.requesting_faculty_id = rf.id
WHERE sr.status = 'pending'

ORDER BY created_at DESC;

-- View for recent changes
CREATE OR REPLACE VIEW v_recent_timetable_changes AS
SELECT 
    th.id,
    th.change_type,
    th.change_reason,
    th.batch,
    COALESCE(th.section, 'N/A') as section,
    th.day_of_week,
    th.time_slot,
    s.name as subject_name,
    f.name as faculty_name,
    r.name as room_name,
    u.username as changed_by_user,
    th.change_details,
    th.created_at
FROM timetable_history th
LEFT JOIN subjects s ON th.subject_id = s.id
LEFT JOIN faculty f ON th.faculty_id = f.id
LEFT JOIN rooms r ON th.room_id = r.id
LEFT JOIN users u ON th.changed_by = u.id
ORDER BY th.created_at DESC
LIMIT 50;

-- 9. Update function to calculate affected classes for leave requests
CREATE OR REPLACE FUNCTION calculate_affected_classes(
    p_faculty_id INTEGER,
    p_start_date DATE,
    p_end_date DATE
) RETURNS INTEGER AS $$
DECLARE
    affected_count INTEGER;
    leave_days TEXT[];
BEGIN
    -- Get day names in leave period
    SELECT ARRAY(
        SELECT DISTINCT TRIM(to_char(d::date, 'Day'))
        FROM generate_series(p_start_date, p_end_date, '1 day'::interval) d
    ) INTO leave_days;
    
    -- Count affected classes
    SELECT COUNT(*)
    INTO affected_count
    FROM timetable t
    WHERE t.faculty_id = p_faculty_id
    AND t.day_of_week = ANY(leave_days)
    AND t.is_active = TRUE;
    
    RETURN affected_count;
END;
$$ LANGUAGE plpgsql;

-- 10. Grant permissions
GRANT ALL PRIVILEGES ON timetable_history TO scheduler_user;
GRANT ALL PRIVILEGES ON reschedule_queue TO scheduler_user;
GRANT USAGE, SELECT ON SEQUENCE timetable_history_id_seq TO scheduler_user;
GRANT USAGE, SELECT ON SEQUENCE reschedule_queue_id_seq TO scheduler_user;

-- 11. Verify table structures
SELECT 
    table_name,
    column_name,
    data_type,
    is_nullable
FROM information_schema.columns
WHERE table_name IN ('leave_requests', 'swap_requests', 'reschedule_queue', 'timetable_history')
ORDER BY table_name, ordinal_position;

-- Success message
SELECT 'Database schema fixes applied successfully!' as status;

CREATE TABLE IF NOT EXISTS timetable_history (
    id SERIAL PRIMARY KEY,
    original_timetable_id INTEGER,
    batch VARCHAR(20) NOT NULL,
    section VARCHAR(1),
    subject_id INTEGER,
    faculty_id INTEGER,
    room_id INTEGER,
    day_of_week VARCHAR(10) NOT NULL,
    time_slot VARCHAR(20) NOT NULL,
    change_type VARCHAR(20) NOT NULL CHECK (change_type IN ('created', 'modified', 'cancelled', 'rescheduled')),
    change_reason VARCHAR(50),
    changed_by INTEGER,
    change_details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Create reschedule_queue table if not exists
CREATE TABLE IF NOT EXISTS reschedule_queue (
    id SERIAL PRIMARY KEY,
    priority INTEGER DEFAULT 5,
    timetable_id INTEGER REFERENCES timetable(id) ON DELETE CASCADE,
    reason VARCHAR(50) NOT NULL,
    original_faculty_id INTEGER REFERENCES faculty(id),
    original_room_id INTEGER REFERENCES rooms(id),
    constraints JSONB,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    error_message TEXT,
    processed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Create indexes
CREATE INDEX IF NOT EXISTS idx_timetable_history_created 
ON timetable_history(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_timetable_history_timetable 
ON timetable_history(original_timetable_id);

CREATE INDEX IF NOT EXISTS idx_timetable_history_change_type 
ON timetable_history(change_type);

CREATE INDEX IF NOT EXISTS idx_reschedule_queue_status 
ON reschedule_queue(status, priority);

CREATE INDEX IF NOT EXISTS idx_reschedule_queue_timetable 
ON reschedule_queue(timetable_id);

-- 4. Grant permissions
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scheduler_user') THEN
        GRANT ALL PRIVILEGES ON timetable_history TO scheduler_user;
        GRANT ALL PRIVILEGES ON reschedule_queue TO scheduler_user;
        GRANT USAGE, SELECT ON SEQUENCE timetable_history_id_seq TO scheduler_user;
        GRANT USAGE, SELECT ON SEQUENCE reschedule_queue_id_seq TO scheduler_user;
    END IF;
END $$;

-- 5. Verify tables created
SELECT 
    'timetable_history' as table_name,
    COUNT(*) as column_count
FROM information_schema.columns
WHERE table_name = 'timetable_history'

UNION ALL

SELECT 
    'reschedule_queue' as table_name,
    COUNT(*) as column_count
FROM information_schema.columns
WHERE table_name = 'reschedule_queue';

-- 6. Add helpful comments
COMMENT ON TABLE timetable_history IS 'Tracks all changes to timetable entries for audit trail';
COMMENT ON TABLE reschedule_queue IS 'Queue for classes that need manual rescheduling';

COMMENT ON COLUMN timetable_history.change_type IS 'Type of change: created, modified, cancelled, or rescheduled';
COMMENT ON COLUMN timetable_history.change_reason IS 'Reason for change: swap_request, leave_substitution, manual, etc.';
COMMENT ON COLUMN timetable_history.change_details IS 'JSON details about the change';

COMMENT ON COLUMN reschedule_queue.status IS 'Current status: pending, processing, completed, or failed';
COMMENT ON COLUMN reschedule_queue.constraints IS 'JSON constraints for rescheduling (dates, requirements, etc.)';

-- Success message
SELECT 'Tables created successfully! You can now approve leave requests.' as status;




-- ==================== DISABLE THE AUTOMATIC TRIGGER ====================
-- This trigger is interfering with our manual leave approval process

-- 1. Drop the trigger
DROP TRIGGER IF EXISTS trigger_leave_approval ON leave_requests;
DROP TRIGGER IF EXISTS trigger_auto_reschedule ON leave_requests;

-- 2. Drop the old function
DROP FUNCTION IF EXISTS trigger_auto_reschedule();
DROP FUNCTION IF EXISTS handle_faculty_leave(integer, date, date, integer);

-- 3. Verify triggers are gone
SELECT 
    trigger_name,
    event_manipulation,
    event_object_table,
    action_statement
FROM information_schema.triggers
WHERE event_object_table = 'leave_requests';

-- Should return empty result (no triggers)

-- 4. Verify functions are gone
SELECT 
    proname as function_name,
    pg_get_functiondef(oid) as definition
FROM pg_proc
WHERE proname IN ('trigger_auto_reschedule', 'handle_faculty_leave');

-- Should return empty result (no functions)

-- Success message
SELECT 'Triggers disabled successfully! Leave requests will now work.' as status;


DO $$ 
DECLARE 
    r RECORD;
BEGIN
    FOR r IN (
        SELECT trigger_name 
        FROM information_schema.triggers 
        WHERE event_object_table = 'leave_requests'
    ) LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON leave_requests', r.trigger_name);
    END LOOP;
END $$;

-- Step 2: Drop old functions that might interfere
DROP FUNCTION IF EXISTS trigger_auto_reschedule() CASCADE;
DROP FUNCTION IF EXISTS handle_faculty_leave(integer, date, date, integer) CASCADE;
DROP FUNCTION IF EXISTS trigger_leave_approval() CASCADE;

-- Step 3: Drop columns that might cause ambiguity
-- First check if 'affected_classes' column exists and is causing issues
DO $$ 
BEGIN
    -- We'll keep the column but make sure it's properly defined
    IF EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'leave_requests' 
        AND column_name = 'affected_classes'
    ) THEN
        -- Column exists, ensure it's JSONB type
        ALTER TABLE leave_requests 
        ALTER COLUMN affected_classes TYPE JSONB USING affected_classes::JSONB;
    ELSE
        -- Column doesn't exist, add it
        ALTER TABLE leave_requests 
        ADD COLUMN affected_classes JSONB;
    END IF;
END $$;

-- Step 4: Ensure all required columns exist
ALTER TABLE leave_requests 
ADD COLUMN IF NOT EXISTS auto_rescheduled BOOLEAN DEFAULT FALSE;

ALTER TABLE leave_requests 
ADD COLUMN IF NOT EXISTS reschedule_details JSONB;

ALTER TABLE leave_requests 
ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP;

ALTER TABLE leave_requests 
ADD COLUMN IF NOT EXISTS approved_by INTEGER REFERENCES users(id);

-- Step 5: Clean up any pending leave requests stuck in processing
UPDATE leave_requests 
SET status = 'pending' 
WHERE status IS NULL OR status = '';

-- Step 6: Verify the schema
SELECT 
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name = 'leave_requests'
ORDER BY ordinal_position;

-- Step 7: List any remaining triggers (should be empty)
SELECT 
    trigger_name,
    event_manipulation,
    action_statement
FROM information_schema.triggers
WHERE event_object_table = 'leave_requests';

-- Step 8: List any remaining functions with 'leave' in name
SELECT 
    proname as function_name,
    pg_get_function_identity_arguments(oid) as arguments
FROM pg_proc
WHERE proname ILIKE '%leave%'
OR proname ILIKE '%reschedule%'
ORDER BY proname;

-- Success message
SELECT 
    '✅ Cleanup complete!' as status,
    'You can now approve leave requests without trigger interference' as message,
    'Restart your Node.js server and test again' as next_step;