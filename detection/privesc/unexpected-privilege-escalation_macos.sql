-- Find processes that run with a lower effective UID than their parent (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation-events.sql
--
-- tags: transient rapid state process escalation
-- platform: darwin
SELECT
  p.pid AS child_pid,
  p.path AS child_path,
  p.name AS child_name,
  p.cmdline AS child_cmdline,
  p.euid AS child_euid,
  p.state AS child_state,
  file.mode AS child_mode,
  hash.sha256 AS child_hash,
  p.parent AS parent_pid,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  pfile.mode AS parent_mode,
  phash.sha256 AS parent_hash
FROM
  processes p
  JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN file AS pfile ON pp.path = pfile.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  p.euid < p.uid
  AND p.path NOT IN (
    '/Library/DropboxHelperTools/Dropbox_u501/dbkextd',
    '/Library/DropboxHelperTools/DropboxHelperInstaller',
    '/usr/bin/login',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/bin/ps',
    '/usr/local/bin/doas',
    '/usr/bin/top'
  )
