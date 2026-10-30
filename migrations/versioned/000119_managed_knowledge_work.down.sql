-- Removing this column while managed work exists would bypass its guard.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM knowledges WHERE managed_work_id <> '') THEN
    RAISE EXCEPTION 'cannot downgrade with managed knowledge records';
  END IF;
END $$;
ALTER TABLE knowledges DROP COLUMN managed_work_id;
