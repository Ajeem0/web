-- ==================== MULTI-SECTION TIMETABLE SCHEMA - FIXED VERSION ====================

-- Add section support to timetable
ALTER TABLE timetable ADD COLUMN IF NOT EXISTS section VARCHAR(10) DEFAULT 'A';
ALTER TABLE timetable ADD COLUMN IF NOT EXISTS week_number INTEGER DEFAULT 1;
ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS affected_classes JSONB;

-- Update unique constraints to include section
DROP INDEX IF EXISTS idx_timetable_batch_slot;
DROP INDEX IF EXISTS idx_timetable_batch_section_slot;
CREATE UNIQUE INDEX idx_timetable_batch_section_slot 
    ON timetable(batch, section, day_of_week, time_slot, academic_year) 
    WHERE is_active = TRUE;

-- Add subjects_weekly_hours table for predefined hours
CREATE TABLE IF NOT EXISTS subjects_weekly_hours (
    id SERIAL PRIMARY KEY,
    subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
    lecture_hours INTEGER DEFAULT 3,
    lab_hours INTEGER DEFAULT 0,
    tutorial_hours INTEGER DEFAULT 0,
    total_hours INTEGER GENERATED ALWAYS AS (lecture_hours + lab_hours + tutorial_hours) STORED,
    min_sessions_per_week INTEGER DEFAULT 2,
    max_sessions_per_week INTEGER DEFAULT 5,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(subject_id)
);

-- Add room equipment and capacity requirements
CREATE TABLE IF NOT EXISTS room_equipment (
    id SERIAL PRIMARY KEY,
    room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    equipment_name VARCHAR(100) NOT NULL,
    quantity INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add subject equipment requirements
CREATE TABLE IF NOT EXISTS subject_equipment_requirements (
    id SERIAL PRIMARY KEY,
    subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE,
    equipment_name VARCHAR(100) NOT NULL,
    required BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add generation attempts log for optimization tracking
CREATE TABLE IF NOT EXISTS timetable_generation_attempts (
    id SERIAL PRIMARY KEY,
    batch VARCHAR(20) NOT NULL,
    section VARCHAR(10),
    academic_year VARCHAR(10),
    algorithm_used VARCHAR(50),
    success BOOLEAN DEFAULT FALSE,
    conflicts_count INTEGER DEFAULT 0,
    room_utilization NUMERIC(5,2),
    faculty_utilization NUMERIC(5,2),
    generation_time_ms INTEGER,
    suggestions JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add constraint satisfaction scores table
CREATE TABLE IF NOT EXISTS constraint_scores (
    id SERIAL PRIMARY KEY,
    timetable_id INTEGER REFERENCES timetable(id) ON DELETE CASCADE,
    constraint_type VARCHAR(50) NOT NULL,
    score NUMERIC(3,2) CHECK (score >= 0 AND score <= 1),
    weight NUMERIC(3,2) DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ==================== FIXED VIEWS FOR MULTI-SECTION ANALYSIS ====================

-- View for section-wise summary
DROP VIEW IF EXISTS v_section_summary CASCADE;
CREATE OR REPLACE VIEW v_section_summary AS
SELECT 
    t.batch,
    t.section,
    t.academic_year,
    COUNT(DISTINCT t.id) as total_classes,
    COUNT(DISTINCT t.subject_id) as unique_subjects,
    COUNT(DISTINCT t.faculty_id) as faculty_count,
    COUNT(DISTINCT t.room_id) as room_count,
    COUNT(DISTINCT t.day_of_week) as days_utilized,
    ROUND(SUM(t.duration_minutes) / 60.0, 2) as total_weekly_hours,
    COUNT(*) FILTER (WHERE t.session_type = 'Lab') as lab_sessions,
    COUNT(*) FILTER (WHERE t.session_type = 'Lecture') as lecture_sessions
FROM timetable t
WHERE t.is_active = TRUE
GROUP BY t.batch, t.section, t.academic_year;

-- FIXED: View for faculty workload across sections with correct column names
DROP VIEW IF EXISTS v_faculty_section_load CASCADE;
CREATE OR REPLACE VIEW v_faculty_section_load AS
SELECT 
    f.id as faculty_id,
    f.name as faculty_name,
    f.department,
    COALESCE(t.batch, 'N/A') as batch,
    COALESCE(t.section, 'N/A') as section,
    COALESCE(t.academic_year, '2024-25') as academic_year,
    COUNT(t.id) as classes_count,
    ROUND(SUM(t.duration_minutes) / 60.0, 2) as weekly_hours,
    f.max_hours_per_week,
    ROUND((COALESCE(SUM(t.duration_minutes), 0) / 60.0) / NULLIF(f.max_hours_per_week, 0) * 100, 2) as utilization_percentage,
    COALESCE(array_agg(DISTINCT s.name) FILTER (WHERE s.name IS NOT NULL), ARRAY[]::VARCHAR[]) as subjects_teaching
FROM faculty f
LEFT JOIN timetable t ON f.id = t.faculty_id AND t.is_active = TRUE
LEFT JOIN subjects s ON t.subject_id = s.id
WHERE f.is_active = TRUE
GROUP BY f.id, f.name, f.department, t.batch, t.section, t.academic_year, f.max_hours_per_week;

-- View for room usage across sections
DROP VIEW IF EXISTS v_room_section_usage CASCADE;
CREATE OR REPLACE VIEW v_room_section_usage AS
SELECT 
    r.id as room_id,
    r.name as room_name,
    r.type as room_type,
    r.capacity,
    COALESCE(t.batch, 'N/A') as batch,
    COALESCE(t.section, 'N/A') as section,
    COALESCE(t.academic_year, '2024-25') as academic_year,
    COUNT(t.id) as total_bookings,
    ROUND(COUNT(t.id) * 100.0 / 36, 2) as utilization_percentage,
    COALESCE(
        array_agg(DISTINCT t.day_of_week || ' ' || t.time_slot ORDER BY t.day_of_week || ' ' || t.time_slot) 
        FILTER (WHERE t.day_of_week IS NOT NULL), 
        ARRAY[]::TEXT[]
    ) as occupied_slots
FROM rooms r
LEFT JOIN timetable t ON r.id = t.room_id AND t.is_active = TRUE
WHERE r.is_active = TRUE
GROUP BY r.id, r.name, r.type, r.capacity, t.batch, t.section, t.academic_year;

-- View for conflict detection across sections
DROP VIEW IF EXISTS v_multi_section_conflicts CASCADE;
CREATE OR REPLACE VIEW v_multi_section_conflicts AS
-- Faculty conflicts across sections
SELECT 
    'Faculty Conflict' as conflict_type,
    'high' as severity,
    f.name as resource_name,
    t1.batch || '-' || t1.section || ' & ' || t2.batch || '-' || t2.section as affected_sections,
    t1.day_of_week,
    t1.time_slot,
    s1.name || ' vs ' || s2.name as conflicting_classes,
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

-- Room conflicts across sections
SELECT 
    'Room Conflict' as conflict_type,
    'high' as severity,
    r.name as resource_name,
    t1.batch || '-' || t1.section || ' & ' || t2.batch || '-' || t2.section as affected_sections,
    t1.day_of_week,
    t1.time_slot,
    s1.name || ' vs ' || s2.name as conflicting_classes,
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

-- Room capacity violations
SELECT 
    'Capacity Violation' as conflict_type,
    'medium' as severity,
    r.name as resource_name,
    t.batch || '-' || t.section as affected_sections,
    t.day_of_week,
    t.time_slot,
    'Room capacity: ' || r.capacity || ', Students: ' || 
    COALESCE((SELECT COUNT(*) FROM students WHERE batch = t.batch), 0) as conflicting_classes,
    t.academic_year
FROM timetable t
JOIN rooms r ON t.room_id = r.id
WHERE t.is_active = TRUE
AND r.capacity < COALESCE((SELECT COUNT(*) FROM students WHERE batch = t.batch), 0);


-- ==================== STORED FUNCTIONS ====================

-- Function to calculate constraint satisfaction score
DROP FUNCTION IF EXISTS calculate_constraint_score(VARCHAR, VARCHAR, VARCHAR);
CREATE OR REPLACE FUNCTION calculate_constraint_score(
    p_batch VARCHAR,
    p_section VARCHAR,
    p_academic_year VARCHAR
)
RETURNS TABLE(
    constraint_name VARCHAR,
    score NUMERIC,
    weight NUMERIC,
    weighted_score NUMERIC,
    details TEXT
) AS $$
DECLARE
    v_total_slots INTEGER := 36; -- 6 days × 6 slots
    v_used_slots INTEGER;
    v_conflicts INTEGER;
    v_faculty_balance NUMERIC;
BEGIN
    -- Calculate used slots
    SELECT COUNT(*) INTO v_used_slots
    FROM timetable
    WHERE batch = p_batch AND section = p_section 
    AND academic_year = p_academic_year AND is_active = TRUE;
    
    -- Calculate conflicts
    SELECT COUNT(*) INTO v_conflicts
    FROM v_multi_section_conflicts
    WHERE affected_sections LIKE '%' || p_batch || '-' || p_section || '%'
    AND academic_year = p_academic_year;
    
    -- Hard constraints
    RETURN QUERY SELECT 
        'No Faculty Conflicts'::VARCHAR,
        CASE WHEN v_conflicts = 0 THEN 1.0 ELSE 0.0 END,
        1.0::NUMERIC,
        CASE WHEN v_conflicts = 0 THEN 1.0 ELSE 0.0 END,
        'Faculty should not be double-booked'::TEXT;
    
    RETURN QUERY SELECT 
        'No Room Conflicts'::VARCHAR,
        CASE WHEN v_conflicts = 0 THEN 1.0 ELSE 0.0 END,
        1.0::NUMERIC,
        CASE WHEN v_conflicts = 0 THEN 1.0 ELSE 0.0 END,
        'Rooms should not be double-booked'::TEXT;
    
    -- Soft constraints
    RETURN QUERY SELECT 
        'Room Utilization'::VARCHAR,
        LEAST(v_used_slots::NUMERIC / NULLIF(v_total_slots, 0), 1.0),
        0.7::NUMERIC,
        LEAST(v_used_slots::NUMERIC / NULLIF(v_total_slots, 0), 1.0) * 0.7,
        'Maximize room usage efficiency'::TEXT;
    
    -- Faculty workload balance
    SELECT COALESCE(STDDEV(utilization_percentage), 0) INTO v_faculty_balance
    FROM v_faculty_section_load
    WHERE batch = p_batch AND section = p_section 
    AND academic_year = p_academic_year
    AND utilization_percentage IS NOT NULL;
    
    RETURN QUERY SELECT 
        'Faculty Workload Balance'::VARCHAR,
        GREATEST(0.0, 1.0 - (v_faculty_balance / 100.0)),
        0.8::NUMERIC,
        GREATEST(0.0, 1.0 - (v_faculty_balance / 100.0)) * 0.8,
        'Balance workload across faculty'::TEXT;
END;
$$ LANGUAGE plpgsql;


-- ==================== INSERT SAMPLE DATA ====================

-- Insert weekly hours for existing subjects
INSERT INTO subjects_weekly_hours (subject_id, lecture_hours, lab_hours, tutorial_hours, min_sessions_per_week, max_sessions_per_week)
SELECT 
    id,
    CASE 
        WHEN type = 'Theory' THEN 3
        WHEN type = 'Practical' THEN 0
        ELSE 2
    END as lecture_hours,
    CASE 
        WHEN type = 'Practical' THEN 4
        ELSE 0
    END as lab_hours,
    CASE 
        WHEN type = 'Tutorial' THEN 1
        ELSE 0
    END as tutorial_hours,
    2 as min_sessions,
    4 as max_sessions
FROM subjects
WHERE NOT EXISTS (
    SELECT 1 FROM subjects_weekly_hours WHERE subject_id = subjects.id
)
ON CONFLICT (subject_id) DO NOTHING;

-- Insert sample room equipment
INSERT INTO room_equipment (room_id, equipment_name, quantity) 
SELECT 
    r.id,
    CASE 
        WHEN r.type = 'Lab' THEN 'Computer'
        WHEN r.type = 'Classroom' THEN 'Projector'
        ELSE 'Audio System'
    END,
    CASE 
        WHEN r.type = 'Lab' THEN LEAST(r.capacity, 50)
        ELSE 1
    END
FROM rooms r
WHERE NOT EXISTS (SELECT 1 FROM room_equipment WHERE room_id = r.id)
AND r.is_active = TRUE
LIMIT 20
ON CONFLICT DO NOTHING;


-- ==================== INDEXES FOR PERFORMANCE ====================

CREATE INDEX IF NOT EXISTS idx_timetable_section 
    ON timetable(batch, section, academic_year) 
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_timetable_faculty_section
    ON timetable(faculty_id, batch, section, academic_year)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_timetable_room_section
    ON timetable(room_id, batch, section, academic_year)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_subjects_weekly_hours_subject 
    ON subjects_weekly_hours(subject_id);

CREATE INDEX IF NOT EXISTS idx_room_equipment_room 
    ON room_equipment(room_id);


-- ==================== VERIFICATION QUERIES ====================

-- Check tables created
SELECT 
    tablename,
    schemaname
FROM pg_tables 
WHERE tablename IN ('subjects_weekly_hours', 'room_equipment', 'subject_equipment_requirements', 
                    'timetable_generation_attempts', 'constraint_scores')
ORDER BY tablename;

-- Check views created
SELECT 
    viewname,
    schemaname
FROM pg_views 
WHERE viewname IN ('v_section_summary', 'v_faculty_section_load', 
                   'v_room_section_usage', 'v_multi_section_conflicts')
ORDER BY viewname;

-- Check indexes created
SELECT 
    indexname,
    tablename
FROM pg_indexes 
WHERE indexname LIKE '%section%'
ORDER BY tablename, indexname;

-- Test view with correct column names
SELECT 
    faculty_name,
    batch,
    section,
    classes_count,
    weekly_hours,
    utilization_percentage
FROM v_faculty_section_load
WHERE batch != 'N/A'
LIMIT 5;

-- Test section summary
SELECT * FROM v_section_summary
ORDER BY batch, section
LIMIT 5;

-- Test constraint scoring
SELECT 
    constraint_name,
    ROUND(score::NUMERIC, 3) as score,
    ROUND(weighted_score::NUMERIC, 3) as weighted_score,
    details
FROM calculate_constraint_score('CS2023', 'A', '2024-25')
ORDER BY weight DESC;


-- ==================== UPDATE EXISTING DATA ====================

-- Update existing timetable entries to have section 'A' by default
UPDATE timetable 
SET section = 'A' 
WHERE section IS NULL;

-- Ensure all faculty have max_hours_per_week set
UPDATE faculty 
SET max_hours_per_week = 25 
WHERE max_hours_per_week IS NULL OR max_hours_per_week = 0;


-- ==================== HELPER FUNCTIONS FOR BACKEND ====================

-- Function to get available sections for a batch
CREATE OR REPLACE FUNCTION get_batch_sections(p_batch VARCHAR, p_academic_year VARCHAR DEFAULT '2024-25')
RETURNS TABLE(section VARCHAR, class_count INTEGER) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        DISTINCT t.section,
        COUNT(t.id)::INTEGER as class_count
    FROM timetable t
    WHERE t.batch = p_batch 
    AND t.academic_year = p_academic_year
    AND t.is_active = TRUE
    GROUP BY t.section
    ORDER BY t.section;
END;
$$ LANGUAGE plpgsql;

-- Function to check if section has conflicts
CREATE OR REPLACE FUNCTION section_has_conflicts(
    p_batch VARCHAR, 
    p_section VARCHAR, 
    p_academic_year VARCHAR DEFAULT '2024-25'
)
RETURNS BOOLEAN AS $$
DECLARE
    v_conflict_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_conflict_count
    FROM v_multi_section_conflicts
    WHERE affected_sections LIKE '%' || p_batch || '-' || p_section || '%'
    AND academic_year = p_academic_year;
    
    RETURN v_conflict_count > 0;
END;
$$ LANGUAGE plpgsql;


-- ==================== COMMENTS ====================

COMMENT ON TABLE subjects_weekly_hours IS 'Stores predefined weekly hours for each subject (lectures + labs + tutorials)';
COMMENT ON TABLE room_equipment IS 'Tracks equipment available in each room for matching with subject requirements';
COMMENT ON TABLE timetable_generation_attempts IS 'Logs all generation attempts for optimization analysis';
COMMENT ON TABLE constraint_scores IS 'Stores CSP constraint satisfaction scores for timetable optimization';

COMMENT ON VIEW v_section_summary IS 'Summary statistics for each section including classes, faculty, and room usage';
COMMENT ON VIEW v_faculty_section_load IS 'Faculty workload analysis across sections with utilization percentages';
COMMENT ON VIEW v_room_section_usage IS 'Room utilization tracking across sections';
COMMENT ON VIEW v_multi_section_conflicts IS 'Detects all types of conflicts across sections (faculty, room, capacity)';

COMMENT ON FUNCTION calculate_constraint_score IS 'Calculates weighted CSP constraint satisfaction score for a section';
COMMENT ON FUNCTION get_batch_sections IS 'Returns all sections for a given batch with class counts';
COMMENT ON FUNCTION section_has_conflicts IS 'Quick check if a section has any conflicts';

COMMENT ON COLUMN timetable.section IS 'Section identifier (A, B, C, etc.) for multi-section support';
COMMENT ON COLUMN timetable.week_number IS 'Week number for rotating schedules (future use)';


-- ==================== FINAL VERIFICATION ====================

DO $$
DECLARE
    v_tables_count INTEGER;
    v_views_count INTEGER;
    v_functions_count INTEGER;
BEGIN
    -- Count created objects
    SELECT COUNT(*) INTO v_tables_count
    FROM pg_tables 
    WHERE tablename IN ('subjects_weekly_hours', 'room_equipment', 'timetable_generation_attempts', 'constraint_scores');
    
    SELECT COUNT(*) INTO v_views_count
    FROM pg_views 
    WHERE viewname IN ('v_section_summary', 'v_faculty_section_load', 'v_room_section_usage', 'v_multi_section_conflicts');
    
    SELECT COUNT(*) INTO v_functions_count
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname = 'public'
    AND p.proname IN ('calculate_constraint_score', 'get_batch_sections', 'section_has_conflicts');
    
    RAISE NOTICE '==================== INSTALLATION SUMMARY ====================';
    RAISE NOTICE 'Tables created: % / 4', v_tables_count;
    RAISE NOTICE 'Views created: % / 4', v_views_count;
    RAISE NOTICE 'Functions created: % / 3', v_functions_count;
    RAISE NOTICE '=============================================================';
    
    IF v_tables_count = 4 AND v_views_count = 4 AND v_functions_count = 3 THEN
        RAISE NOTICE 'SUCCESS: All database objects created successfully!';
        RAISE NOTICE 'You can now use the multi-section timetable features.';
    ELSE
        RAISE WARNING 'Some objects may not have been created. Please check the logs.';
    END IF;
END $$;


-- Add section column to students if not exists
ALTER TABLE students ADD COLUMN IF NOT EXISTS section VARCHAR(10);

-- Create index for section queries
CREATE INDEX IF NOT EXISTS idx_students_batch_section 
    ON students(batch, section) 
    WHERE is_active = TRUE;

-- Update students table comment
COMMENT ON COLUMN students.section IS 'Section identifier (A, B, C, D, E) for multi-section batches';

-- Add day_off column to track which day each section has off
ALTER TABLE timetable ADD COLUMN IF NOT EXISTS day_off VARCHAR(20);

-- Add a table to store section preferences
CREATE TABLE IF NOT EXISTS section_preferences (
    id SERIAL PRIMARY KEY,
    batch VARCHAR(20) NOT NULL,
    section VARCHAR(10) NOT NULL,
    day_off VARCHAR(20), -- The day this section has off
    academic_year VARCHAR(10) DEFAULT '2024-25',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(batch, section, academic_year)
);

COMMENT ON TABLE section_preferences IS 'Stores preferences for each section including their day off';