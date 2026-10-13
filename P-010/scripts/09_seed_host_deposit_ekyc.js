/**
 * P-010 VinStay — DB SEED for dynamic battery 09 (host↔host IDOR, deposit happy-path+IDOR, eKYC/contract A18).
 *
 * Seeds DIRECTLY into the isolated Postgres (the legal way to cross multi-actor state barriers the HTTP flow
 * cannot reach alone). Everything tagged SECTEST- for teardown. Idempotent: deletes prior SECTEST rows first.
 *
 * Reuses the app's EXACT crypto so seeded ciphertext decrypts in-app:
 *   - scrypt password hash (node defaults N=16384,r=8,p=1, keylen 64) -> `scrypt$<saltHex>$<keyHex>`
 *   - AES-256-GCM over HKDF-SHA256(master=AES_SECRET_KEY, salt 'vinstay.v1', info 'phone:aes-256-gcm')
 *     ciphertext format  v1:<ivB64url>:<tagB64url>:<ctB64url>   (matches PhoneService.encrypt)
 *
 * Run (from a clean dir, NODE_PATH -> backend node_modules so @prisma/client + generated client resolve):
 *   NODE_PATH=<backend>/node_modules DATABASE_URL=... AES_SECRET_KEY=... node 09_seed_host_deposit_ekyc.js
 * Prints a JSON blob of seeded ids/refs to stdout (last line) for the python attacker to consume.
 */
'use strict';
const crypto = require('node:crypto');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// --- app-identical crypto ---------------------------------------------------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw.normalize('NFKC'), salt, 64); // node defaults = password-hasher.ts
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}
const MASTER = process.env.AES_SECRET_KEY && process.env.AES_SECRET_KEY.length >= 16
  ? process.env.AES_SECRET_KEY : 'vinstay-dev-only-secret-DO-NOT-USE-IN-PROD';
const AES_KEY = Buffer.from(crypto.hkdfSync('sha256', MASTER, 'vinstay.v1', 'phone:aes-256-gcm', 32));
const HMAC_KEY = Buffer.from(crypto.hkdfSync('sha256', MASTER, 'vinstay.v1', 'phone:hmac-blind-index', 32));
function aesEncrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  const tag = c.getAuthTag();
  return ['v1', iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join(':');
}
const phoneHash = (e164) => crypto.createHmac('sha256', HMAC_KEY).update(e164).digest('hex');

// --- known HTTP-created principals (captured from signup) --------------------
const TENANT_A = process.env.TENANT_A;   // required via env
const TENANT_B = process.env.TENANT_B;
const LANDLORD_A = process.env.LANDLORD_A;
const LANDLORD_B = process.env.LANDLORD_B;

const PW = '<REDACTED_PASSWORD>';
const nowISO = () => new Date().toISOString();

async function roleId(code) {
  const r = await prisma.role.upsert({ where: { code }, update: {}, create: { code, name: code } });
  return r.id;
}

async function cleanup() {
  // scope every child on the SECTEST viewings/units so HTTP-created rows (e.g. depositCode DEP-SECTEST-*) are caught.
  const vwSec = { viewing: { bookingRefCode: { startsWith: 'SECTEST' } } };
  const depSec = { deposit: { OR: [{ depositCode: { startsWith: 'SECTEST' } }, vwSec] } };
  await prisma.$transaction([
    prisma.escrowTransaction.deleteMany({ where: { OR: [{ bankRefNumber: { startsWith: 'SECTEST' } }, depSec] } }),
    prisma.contract.deleteMany({ where: { OR: [{ contractNumber: { startsWith: 'SECTEST' } }, { unit: { unitCode: { startsWith: 'SECTEST' } } }] } }),
    prisma.identityVerification.deleteMany({ where: { OR: [{ providerRefId: { startsWith: 'SECTEST' } }, depSec] } }),
    prisma.holdingDeposit.deleteMany({ where: { OR: [{ depositCode: { startsWith: 'SECTEST' } }, vwSec] } }),
    prisma.signedDocument.deleteMany({ where: { OR: [{ storageKey: { contains: 'SECTEST' } }, { mandate: null, deposit: null, contract: null } ] } }),
    prisma.dispatchTicket.deleteMany({ where: vwSec }),
    prisma.viewing.deleteMany({ where: { bookingRefCode: { startsWith: 'SECTEST' } } }),
    prisma.exclusiveMandate.deleteMany({ where: { contractNumber: { startsWith: 'SECTEST' } } }),
    prisma.doorAccessKey.deleteMany({ where: { unit: { unitCode: { startsWith: 'SECTEST' } } } }),
    prisma.unitMedia.deleteMany({ where: { unit: { unitCode: { startsWith: 'SECTEST' } } } }),
    prisma.unit.deleteMany({ where: { unitCode: { startsWith: 'SECTEST' } } }),
    prisma.building.deleteMany({ where: { buildingCode: { startsWith: 'SECTEST' } } }),
    prisma.fieldHost.deleteMany({ where: { profile: { email: { startsWith: 'sectest.host' } } } }),
    prisma.auditLog.deleteMany({ where: { actor: { OR: [{ email: { startsWith: 'sectest.host' } }, { email: 'sectest.opsadmin@example.com' } ] } } }),
    prisma.profile.deleteMany({ where: { email: { startsWith: 'sectest.host' } } }),
    prisma.profile.deleteMany({ where: { email: 'sectest.opsadmin@example.com' } }),
  ]);
}

async function main() {
  if (!TENANT_A || !TENANT_B || !LANDLORD_A || !LANDLORD_B) {
    throw new Error('Set TENANT_A/TENANT_B/LANDLORD_A/LANDLORD_B env to the signup profile ids.');
  }
  await cleanup();

  const fieldHostRole = await roleId('field_host');
  const opsAdminRole = await roleId('ops_admin');

  // ops_admin "system actor" for VietQR markPaid unmatched/expiry branches
  const opsAdmin = await prisma.profile.create({
    data: { id: crypto.randomUUID(), roleId: opsAdminRole, email: 'sectest.opsadmin@example.com',
            fullName: 'SECTEST OpsAdmin', passwordHash: hashPassword(PW), isActive: true, isPhoneVerified: true },
  });

  // Building + units (owned by landlordA, AVAILABLE, verified)
  const building = await prisma.building.create({
    data: { buildingCode: 'SECTEST-B1', zoneName: 'SECTEST Sapphire', totalFloors: 40,
            lobbyLatitude: '20.9500000', lobbyLongitude: '105.9000000' },
  });
  async function mkUnit(code, floor, door) {
    const u = await prisma.unit.create({
      data: {
        unitCode: code, buildingId: building.id, landlordId: LANDLORD_A, floorNumber: floor,
        layoutType: 'STUDIO', carpetAreaM2: '30.00', baseRentPrice: '8000000', managementFee: '500000',
        marketAvgPrice: '8500000', doorLockType: 'ELECTRONIC_PIN', doorNumber: door, furnishing: 'FULL',
        amenities: ['AC', 'FRIDGE'], isVerified: true, verifiedAt: new Date(), status: 'AVAILABLE',
        securityDeposit: '8000000',
      },
    });
    await prisma.unitMedia.create({ data: { unitId: u.id, url: 'https://sectest.example/img.png', category: 'living_room', order: 0 } });
    return u;
  }
  const unitHA = await mkUnit('SECTEST-U-HA', 10, 'A10');
  const unitHB = await mkUnit('SECTEST-U-HB', 11, 'B11');
  const unitDep = await mkUnit('SECTEST-U-DEP', 12, 'C12');
  const unitCon = await mkUnit('SECTEST-U-CON', 14, 'E14');

  // Two Field Hosts (profile + FieldHost), SALE+INSPECTOR, online, phone-verified
  async function mkHost(tag, phone, zone) {
    const p = await prisma.profile.create({
      data: { id: crypto.randomUUID(), roleId: fieldHostRole, email: `sectest.host${tag}@example.com`.toLowerCase(),
              fullName: `SECTEST Host${tag}`, passwordHash: hashPassword(PW), isActive: true,
              isPhoneVerified: true, phoneEnc: aesEncrypt(phone), phoneHash: phoneHash(phone) },
    });
    const fh = await prisma.fieldHost.create({
      data: { profileId: p.id, assignedZone: zone, roles: ['SALE', 'INSPECTOR'],
              rfidCardNumber: `SECTEST-${tag}`, dutyStatus: 'ONLINE_AVAILABLE' },
    });
    return { profileId: p.id, hostId: fh.id };
  }
  const hostA = await mkHost('A', '+84912300001', 'SECTEST Sapphire');
  const hostB = await mkHost('B', '+84912300002', 'SECTEST Sapphire');

  // Viewings + OFFERED assigned tickets (host A drives lifecycle live; host B owns its own)
  const slot = new Date(Date.now() + 2 * 3600 * 1000);
  async function mkViewing(ref, unitId, tenantId, phone) {
    return prisma.viewing.create({
      data: { bookingRefCode: ref, unitId, tenantId, contactName: 'SECTEST Viewer',
              contactPhoneEnc: aesEncrypt(phone), contactPhoneHash: phoneHash(phone),
              viewingSlot: slot, status: 'PENDING_CONFIRMATION' },
    });
  }
  const vHA = await mkViewing('SECTEST-VW-HA', unitHA.id, TENANT_A, '+84988000001');
  const vHB = await mkViewing('SECTEST-VW-HB', unitHB.id, TENANT_B, '+84988000002');
  const tHA = await prisma.dispatchTicket.create({
    data: { viewingId: vHA.id, hostId: hostA.hostId, tier: 1, slaSeconds: 180, status: 'OFFERED', offeredAt: new Date() },
  });
  const tHB = await prisma.dispatchTicket.create({
    data: { viewingId: vHB.id, hostId: hostB.hostId, tier: 1, slaSeconds: 180, status: 'OFFERED', offeredAt: new Date() },
  });

  // Deposit happy-path precondition: a viewing already in CLOSING, owned by tenantA, unit AVAILABLE.
  const vDep = await prisma.viewing.create({
    data: { bookingRefCode: 'SECTEST-VW-DEP', unitId: unitDep.id, tenantId: TENANT_A, contactName: 'SECTEST Depositor',
            contactPhoneEnc: aesEncrypt('+84988000003'), contactPhoneHash: phoneHash('+84988000003'),
            viewingSlot: slot, status: 'CLOSING', viewingStartedAt: new Date(), viewEndedAt: new Date() },
  });

  // Inspection IDOR: an ExclusiveMandate "inspecting", assigned to hostA (meta.hostId=hostA).
  const consForm = { building: 'SECTEST-B1', floor: 14, door: 'INS1', areaM2: 30, askRent: 8000000,
                     suggestedDeposit: 8000000, leaseTerm: 'long', furnished: true, locks: ['smart'], note: null };
  const mandate = await prisma.exclusiveMandate.create({
    data: {
      unitId: unitHA.id, contractNumber: 'SECTEST-MANDATE-1', status: 'PENDING_INSPECTION', signedAt: new Date(),
      doorAccessConfig: { consignment: { form: consForm, stage: 'inspecting', hostId: hostA.hostId,
                                         offeredAt: nowISO(), hostAcceptedAt: nowISO() } },
    },
  });

  // ---- eKYC/contract downstream chain (seeded; the only creator A18 is hard-503'd) ----
  const vCon = await prisma.viewing.create({
    data: { bookingRefCode: 'SECTEST-VW-CON', unitId: unitCon.id, tenantId: TENANT_A, contactName: 'SECTEST Lessee',
            contactPhoneEnc: aesEncrypt('+84988000004'), contactPhoneHash: phoneHash('+84988000004'),
            viewingSlot: slot, status: 'HOLDING', viewingStartedAt: new Date(), viewEndedAt: new Date() },
  });
  const depCon = await prisma.holdingDeposit.create({
    data: { depositCode: 'SECTEST-DEP-CON', viewingId: vCon.id, unitId: unitCon.id, amount: '2000000',
            vietqrRef: 'SECTEST-VQ-CON', transferContent: 'SECTEST COC CON', paymentStatus: 'PAID_HOLDING',
            paidAt: new Date(), termsAcceptedAt: new Date(), termsVersion: 'HOLD-2026.10-v1', holdHours: 168,
            expiresAt: new Date(Date.now() + 168 * 3600 * 1000) },
  });
  const kyc = { fullName: 'SECTEST Nguyen Van A', idNumber: '001099012345', dob: '01/01/1995',
                issuedDate: '01/01/2021', address: 'SECTEST 123 Ocean Park, Ha Noi' };
  const identity = await prisma.identityVerification.create({
    data: { tenantId: TENANT_A, depositId: depCon.id, providerName: 'FPT.AI', providerRefId: 'SECTEST-EKYC-1',
            confidenceScore: 0.99, faceMatchScore: 0.98, status: 'VERIFIED', verifiedDataRef: aesEncrypt(JSON.stringify(kyc)),
            consentAt: new Date(), consentVersion: 'KYC-2026.10-v1', verifiedAt: new Date() },
  });
  const start = new Date(); const end = new Date(Date.now() + 365 * 24 * 3600 * 1000);
  const contract = await prisma.contract.create({
    data: { contractNumber: 'SECTEST-CT-1', unitId: unitCon.id, holdingDepositId: depCon.id, tenantId: TENANT_A,
            landlordId: LANDLORD_A, leaseTermMonths: 12, startDate: start, endDate: end, monthlyRentPrice: '8000000',
            securityDepositAmount: '8000000', paymentCycleMonths: 1, status: 'AWAITING_TENANT_SIGN', signedAt: new Date() },
  });

  const out = {
    opsAdminId: opsAdmin.id,
    buildingId: building.id,
    units: { unitHA: unitHA.unitCode, unitHB: unitHB.unitCode, unitDep: unitDep.unitCode, unitCon: unitCon.unitCode },
    hostA, hostB,
    refs: { vHA: vHA.bookingRefCode, vHB: vHB.bookingRefCode, vDep: vDep.bookingRefCode, vCon: vCon.bookingRefCode },
    ticketHA: tHA.id, ticketHB: tHB.id,
    mandateId: mandate.id,
    depositConId: depCon.id, identityId: identity.id,
    contractId: contract.id, contractNumber: contract.contractNumber,
  };
  console.log('SEED_JSON ' + JSON.stringify(out));
  if (process.env.SEED_OUT) require('node:fs').writeFileSync(process.env.SEED_OUT, JSON.stringify(out, null, 2));
}

main().then(() => prisma.$disconnect()).catch(async (e) => { console.error(e); await prisma.$disconnect(); process.exit(1); });
