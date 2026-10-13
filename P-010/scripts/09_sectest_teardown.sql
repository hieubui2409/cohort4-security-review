-- P-010 SECTEST- teardown for battery 09 (host IDOR + deposit + eKYC/contract).
-- Removes every SECTEST row created by scripts/09_seed_host_deposit_ekyc.js and the HTTP battery, FK-safe order.
-- (The whole Postgres container vinstay-p010-sectest2-pg is also destroyed at teardown — this SQL proves 0 remain.)
BEGIN;
-- children of SECTEST viewings / deposits first
DELETE FROM escrow_transactions WHERE bank_ref_number LIKE 'SECTEST%'
   OR deposit_id IN (SELECT hd.id FROM holding_deposits hd JOIN viewings v ON v.id=hd.viewing_id WHERE v.booking_ref_code LIKE 'SECTEST%');
DELETE FROM contracts WHERE contract_number LIKE 'SECTEST%'
   OR unit_id IN (SELECT id FROM units WHERE unit_code LIKE 'SECTEST%');
DELETE FROM identity_verifications WHERE provider_reference_id LIKE 'SECTEST%'
   OR deposit_id IN (SELECT hd.id FROM holding_deposits hd JOIN viewings v ON v.id=hd.viewing_id WHERE v.booking_ref_code LIKE 'SECTEST%');
DELETE FROM holding_deposits WHERE deposit_code LIKE 'SECTEST%'
   OR viewing_id IN (SELECT id FROM viewings WHERE booking_ref_code LIKE 'SECTEST%');
DELETE FROM signed_documents WHERE storage_key LIKE '%SECTEST%';
DELETE FROM dispatch_tickets WHERE viewing_id IN (SELECT id FROM viewings WHERE booking_ref_code LIKE 'SECTEST%');
DELETE FROM viewings WHERE booking_ref_code LIKE 'SECTEST%';
DELETE FROM exclusive_mandates WHERE contract_number LIKE 'SECTEST%';
DELETE FROM door_access_keys WHERE unit_id IN (SELECT id FROM units WHERE unit_code LIKE 'SECTEST%');
DELETE FROM unit_media WHERE unit_id IN (SELECT id FROM units WHERE unit_code LIKE 'SECTEST%');
DELETE FROM units WHERE unit_code LIKE 'SECTEST%';
DELETE FROM buildings WHERE building_code LIKE 'SECTEST%';
DELETE FROM field_hosts WHERE profile_id IN (SELECT id FROM profiles WHERE email LIKE 'sectest.host%');
DELETE FROM audit_logs WHERE actor_id IN (SELECT id FROM profiles WHERE email LIKE 'sectest.host%' OR email='sectest.opsadmin@example.com');
DELETE FROM profiles WHERE email LIKE 'sectest.host%' OR email='sectest.opsadmin@example.com';
-- NOTE: the HTTP-signup principals (sectest.tenant*/landlord*) are left; the container is dropped entirely at teardown.
COMMIT;
