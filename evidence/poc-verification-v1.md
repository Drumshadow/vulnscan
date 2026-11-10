outcomes by item kind:
  nc_benign  n=  24  confirmed 4 (17%)  not_reproduced 5 (21%)  unverifiable 15 (62%)  unchecked 0 (0%)
  nc_fixed   n=  44  confirmed 13 (30%)  not_reproduced 7 (16%)  unverifiable 24 (55%)  unchecked 0 (0%)
  nc_vuln    n=  90  confirmed 12 (13%)  not_reproduced 20 (22%)  unverifiable 58 (64%)  unchecked 0 (0%)

confirmations on patched/benign code (17; AT FIX SITE = likely false, elsewhere = maybe a real other bug):
   ('GHSA-2wxc-x7rj-hg8f:nc_fixed', 0, 'elsewhere', 'Potential Command Injection in Remote SCP Command Construction')
   ('GHSA-39mj-jf6j-2qj3:nc_fixed', 0, 'elsewhere', 'Unhandled ValueError in `_find_previous_startxref_pos` causing DoS')
   ('GHSA-9xwg-3r6f-jcx2:nc_fixed', 0, 'AT FIX SITE', 'Path Traversal Bypass via Case-Insensitive Filesystem and Symlinks')
   ('GHSA-fp3f-mc75-235c:nc_fixed', 0, 'elsewhere', 'Missing token length validation in parse_bfchar')
   ('GHSA-gh4c-6fx4-qh6g:nc_fixed', 0, 'AT FIX SITE', 'Uncontrolled Resource Consumption (Decompression Bomb) in DeflateDecoder')
   ('GHSA-gh4c-6fx4-qh6g:nc_fixed', 1, 'elsewhere', 'Uncontrolled Resource Consumption (Decompression Bomb) in GzipDecoder')
   ('GHSA-hp3v-5vw7-fx9w:nc_fixed', 0, 'elsewhere', 'Missing input validation in guarded_setattr allows bypassing attribute name restrictions')
   ('GHSA-mxm6-v9r6-r94c:nc_fixed', 0, 'AT FIX SITE', 'HTML Entity Stripping Bypasses Dangerous URL Prefix Checks')
   ('GHSA-mxm6-v9r6-r94c:nc_fixed', 1, 'AT FIX SITE', 'Missing Validation for `xlink:href` Attribute')
   ('GHSA-qr67-gv47-xwwh:nc_fixed', 0, 'elsewhere', 'OS Command Injection via SSH Config Match exec')
   ('GHSA-qwm4-qh6w-59xr:nc_fixed', 0, 'elsewhere', 'Unbounded Cache Growth in LinkHash.find_hash_url_fragment')
   ('GHSA-qwm4-qh6w-59xr:nc_fixed', 1, 'elsewhere', 'Unsanitized subdirectory fragment extraction')
   ('GHSA-r3r9-wp5j-pq5g:nc_fixed', 0, 'elsewhere', 'Broken CIDR matching disables IP allow/deny lists')
   ('facelessuser/pymdown-extensions@0b83e4b95300:nc_benign', 0, 'elsewhere', 'Path Traversal via `file://` URL Scheme')
   ('ronf/asyncssh@1c3212db930f:nc_benign', 0, 'elsewhere', 'Command Injection via Match exec directive')
   ('ronf/asyncssh@1c3212db930f:nc_benign', 2, 'elsewhere', 'Use of Broken Cryptographic Algorithm (SHA-1)')
   ('tinytag/tinytag@196cf74030ac:nc_benign', 0, 'elsewhere', 'Arbitrary File Read')

| variant | pair acc | recall | precision | benign flagged | fix-site flagged |
|---|---|---|---|---|---|
| unverified | 18% | 21% | 20% | 28% | 9% |
| drop not_reproduced | 12% | 15% | 17% | 26% | 9% |
| confirmed + unverifiable | 12% | 15% | 17% | 26% | 9% |
| confirmed only | 2% | 2% | 9% | 6% | 3% |
