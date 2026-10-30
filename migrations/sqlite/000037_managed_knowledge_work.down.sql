-- Removing this column while any managed document exists would reopen native
-- processing for that document. Refuse the downgrade until all such data is
-- safely retired by an explicit migration.
CREATE TEMP TABLE managed_work_downgrade_guard (managed_count INTEGER CHECK (managed_count = 0));
INSERT INTO managed_work_downgrade_guard SELECT COUNT(*) FROM knowledges WHERE managed_work_id <> '';
DROP TABLE managed_work_downgrade_guard;
ALTER TABLE knowledges DROP COLUMN managed_work_id;
