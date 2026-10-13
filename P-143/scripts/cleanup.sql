-- P-143 dynamic-test cleanup (authorized review). Verified to run clean on the dev stack DB.
-- Load/race tests tag invoices with invoice_number LIKE 'SECTEST%'. NO ACTION FKs (upload_events,
-- invoice_tax_assessments, approvals) are cleared first; invoice_lines/line_matches/discrepancies/
-- invoice_po_links cascade. Run:  docker exec -i p-143-db-1 psql -U postgres -d p143 < cleanup.sql
BEGIN;
CREATE TEMP TABLE _sectest_inv AS
  SELECT id FROM invoices WHERE invoice_number LIKE 'SECTEST%';
DELETE FROM upload_events           WHERE invoice_id IN (SELECT id FROM _sectest_inv) OR duplicate_of IN (SELECT id FROM _sectest_inv);
DELETE FROM invoice_tax_assessments WHERE invoice_id IN (SELECT id FROM _sectest_inv);
DELETE FROM approvals               WHERE invoice_id IN (SELECT id FROM _sectest_inv);
DELETE FROM invoices                WHERE id IN (SELECT id FROM _sectest_inv);
COMMIT;

-- Orphan upload_batches/files left by the duplicate-upload race and the SECTEST tenants/users
-- (<REDACTED_EMAIL>, <REDACTED_EMAIL>, <REDACTED_EMAIL>, org 'Org B SECTEST') have child-row FKs
-- (files.batch_id, login_attempts, sessions). The whole dev DB is an ephemeral Docker volume, so the
-- complete and guaranteed teardown is:
--   docker compose -f deploy/compose.yml down -v     (drops pgdata + miniodata volumes)
