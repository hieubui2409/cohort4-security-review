-- P-010 SECTEST- teardown: remove all write-load artifacts created by
-- scripts/07_idor_bfla_upload_load_battery.py (Battery 3). Children (dispatch_tickets,
-- holding_deposits) are removed before the parent viewings to satisfy FKs.
-- Records are tagged by contact_name LIKE 'SECTEST%' (and tenant_note 'SECTEST-%').
BEGIN;
DELETE FROM dispatch_tickets
 WHERE viewing_id IN (SELECT id FROM viewings WHERE contact_name LIKE 'SECTEST%');
DELETE FROM holding_deposits
 WHERE viewing_id IN (SELECT id FROM viewings WHERE contact_name LIKE 'SECTEST%');
DELETE FROM viewings WHERE contact_name LIKE 'SECTEST%';
COMMIT;
