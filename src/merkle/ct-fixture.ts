// Reused unchanged from systemslibrarian/crypto-lab-merkle-proofs at 70f22d67d562269b6a76aac3c03944572ff367e7.
// Historical pinned-root fixture; no fresh CT service or tree-head signature claim.
/**
 * ct-fixture.ts — A REAL Certificate Transparency inclusion proof, pinned.
 *
 * Fetched 2026-07-11 from Google's `argon2026h1` CT log (RFC 6962 API):
 *   GET /ct/v1/get-sth                       → tree_size + sha256_root_hash
 *   GET /ct/v1/get-entry-and-proof?leaf_index=1234567890&tree_size=2807499968
 *
 * The entry is a Let's Encrypt precertificate for `drvpn.cdm.ge`, logged
 * 2025-12-08T02:30:57Z. `leafInputB64` is the exact MerkleTreeLeaf structure the
 * log hashes (version ∥ leaf_type ∥ timestamp ∥ entry_type ∥ the certificate);
 * its RFC 6962 leaf hash is SHA-256(0x00 ∥ leafInput) — the same rule as every
 * other leaf in this lab.
 *
 * Everything needed to verify is pinned, so the check is fully offline and
 * reproducible forever: the tree of THIS size had THIS root, and this entry is
 * provably inside it. (In production a verifier would also check the log's
 * ECDSA signature over the tree head; here the head is pinned instead.)
 */

export const CT_FIXTURE = {
  logName: "Google 'Argon2026h1' log",
  logUrl: 'https://ct.googleapis.com/logs/us1/argon2026h1/',
  fetchedOn: '2026-07-11',
  certSubject: 'drvpn.cdm.ge',
  certIssuer: "Let's Encrypt R13",
  loggedAt: '2025-12-08T02:30:57Z',
  entryKind: 'precertificate',
  leafIndex: 1234567890,
  treeSize: 2807499968,
  sthTimestamp: 1783770558432,
  rootHashB64: '0rVwWDwyjKbhj6cAUnb/oaW0vvN1JXCKncLeQl5rCd8=',
  leafInputB64:
    'AAAAAAGa+8w9aAABAlSQhgtJirc8ahLyekmtX+Iw+v46yPYRLJt9Cq1GlB0AA9gwggPUoAMCAQICEgUqpSDn/yqBk/GLysiOndSVtTANBgkqhkiG9w0BAQsFADAzMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDEMMAoGA1UEAxMDUjEzMB4XDTI1MTIwODAxMzIyN1oXDTI2MDMwODAxMzIyNlowFzEVMBMGA1UEAxMMZHJ2cG4uY2RtLmdlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2i2houiMyoorY6WalwwHgX6W8krKUATZYD2U26qHGf7XnbVlWpkQyijMI2R6qhyTTysluYdjFMmZemJAU/BAgZA7DKnPCsPJxBOkJ26Aj6rSxH4bGp8CveSvtP3Q5JeTH+/2oXzNxI63m/ISvSMU7WtKW4rTorwEf1L7emaGKvmGoho+d9bSD6c7IIoiwntSA1FBfU59t2f23MoCkZZwJTI4gb84yK65k+VtqyNFKyS/GLowFR/ufKA3qQXAv5nXZ3IdGvCXLg3gIZPGkg8Yr5X8HsbqRkDQfg2DojS7tpPjfX6Wt8HC1Nkgo9d8QM0GUEjy02S/LUWhdar/0UaZS/6lvcqxro9lAduUUH+7XjIFe0pS3Pqz2a9U7G/LWXBDy9+EfIYQrCw8lPVKC2+DnT0qmUFHLL0WTvw6W6D8ExM46FykXDrSv1i7EXC6PyFHM9MfZh45Rl9CCXS+a4FvcOLualRaqy/kF8y7kyqRPQZmrYvh4Pjj5sEu3BoKkzStPumiyh6ZGTr9D2xpHRKGTKYxUZMqvccBFubaIutsnTjH7SoESuiue4JptePgxxClnhtB+IXUiGBH8cfDxJ2p9kXVUYDJon+ennYdbuZQDTrX13ykUjaJSNnR4l7+FFoADJ1sRh2tzbHhHxRELcaU9Jmmqf3Rphg1Y6ZmEir+rZMCAwEAAaOCARQwggEQMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUggfl3uch7f9e4GE5OKCADJWfCdcwHwYDVR0jBBgwFoAU56ufDywzoFPTXk94yLKEDjvWkjMwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzAChhdodHRwOi8vcjEzLmkubGVuY3Iub3JnLzAXBgNVHREEEDAOggxkcnZwbi5jZG0uZ2UwEwYDVR0gBAwwCjAIBgZngQwBAgEwLgYDVR0fBCcwJTAjoCGgH4YdaHR0cDovL3IxMy5jLmxlbmNyLm9yZy81NC5jcmwAAA==',
  auditPathB64: [
    'E6ueKzTzCSkHGJEtPFZ4Gk6wvobkiUaEsqdLEiCKlzc=',
    'F29slUbWxsAipWrmu8SYNCtSDQVymHvP566c1S6vnYk=',
    'hEx7zhEbS1bGl+TfAfChs/Hd7F1rCpy4aI+snEVf00Y=',
    'XJsEczUz0lMio1p5xLSmSfJ5XWrK8kbYUaOTKXHFY90=',
    'g0d+CLqxEkVhjCpOMUd9VyvR+YlDEQWq7aVhjs8ndxg=',
    'XnAoYOcU0EXHnJQAjtHgxj1Fl43lxA+Fa0n2xLW7VqU=',
    'CLfyxu+vrejO32BB2+hypWE3GJBFoBvTkd4sqjCWGnQ=',
    '95CQZuZ1AHE6TE7CLBm378JjQLtrUsa258xOW9rhmSE=',
    'I4BCKxDZjy4GnNK2XDBGkXhD1sP/qfbUu5JhIiOmuJE=',
    'QO9aLelbBS7dEkYHl061+9j4Vl911Df6D1Oi1e0bFwg=',
    'IkuwMA7sjvQ4t3ocNFa+rljqsQMjfiB2aXtnKe1BAwU=',
    'xAIvYLeIDFnv92NZQi4B0xaZzYqLlvWFZ9P9+Uk/+yA=',
    'VLs6AoILi3emjsZHmJAod9AmdaFTXus1bsHIhDJYMhA=',
    'bYb+k0MS78EpaX4UcZi7eRPfwrKpEc/GH8BR7jZVmqc=',
    'M10kAzVdcFyHaf1nqjJ6ECVniECZkai08Rbx+n0E+P4=',
    '41MvH6DoAO4ND8Wk/EphtRCNizKGpg6UYwSpWbn1ku0=',
    'rx/cYjmGayZ43o4ms8FSsPTDCCOGRIZ6j3/C16qp+84=',
    '6hweeBNtHTto6HNg0LmI1UC+eidRPFH1BKwo3SqYqYo=',
    '2E24xiFMeZoloPk5MmRAEjpcUDstlh1G1IxNQZ38WVU=',
    'Zf72zVA5jX4hkxRk6BuCtI/si4edTghQYkbSOwT/BfI=',
    'YP6y3mUWzoo22cZ+0tm/GNSfmmhvMD1mvGNajKP4oHA=',
    'wf1lANk/yYqLNUBfPUPcSQPd3RocNJJpU30k41z97ds=',
    'Rmh8vSsIxi0vaGrHOIU9Dl1FMu7bLrdmA/zjepe1ZLU=',
    'hUQsCjJus8+dGlo09R9JEO4YiNn1qZAJOWkVMqLYfNM=',
    'HrjNQeyFjcX4hSBjAMvVgsbmzOeILdmkh+Ub5QENIms=',
    '+iilp4VmYzGgQFy9fl2R7pJyAbS+gx08Z6g82ATLGvs=',
    '0RYmgHWPxhCjTFUiW5iQrG1Yobx5YEjteswvIjfaNrg=',
    '2S1ZDiKZz90SnPXiapm9TISvNEw7BSfw4qE2dRT8mAk=',
    'tN3HkklCtfkR/pMDN7JtZWYPEmSiUJ6KOAb5fwYuc8U=',
    'INnIe3gCmDPcwIup8JPUEqMzej10CZMNv179V4/SLeU=',
    '7UIUa8XFNxQ68INsz0n3o8Fh3Z1QQumC+7ooYCnuZ9U=',
    'H4R1rBMRYndqYcB7Ge+d4HG+dpXrpRcQCvRen7uY6yQ=',
  ],
} as const;
