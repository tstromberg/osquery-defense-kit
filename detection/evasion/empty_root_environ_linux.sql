-- Find programs which spawn root children without propagating environment variables
--
-- references:
--   * https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
--
-- Effectively:
-- SELECT COUNT(key) AS env_count, processes.pid FROM processes LEFT JOIN process_envs ON processes.pid = process_envs.pid GROUP BY processes.pid HAVING env_count == 0;
-- tags: persistent state daemon process seldom
-- platform: linux
SELECT COUNT(pe.key) AS env_count,
  -- Child
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM processes p0
  LEFT JOIN process_envs pe ON p0.pid = pe.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
-- Optimization technique to avoid checksumming parents
-- unless they match our conditions. This way we only have 15-20 processes
-- to deal with
WHERE p0.pid IN (
    SELECT pid
    FROM processes
    WHERE euid == 0
      AND NOT parent IN (0, 2)
      AND NOT path = ""
      AND NOT name IN (
        'applydeltarpm',
        'bwrap',
        'cupsd',
        'dhcpcd',
        'crond',
        'auditd',
        'NetworkManager',
        'lightdm',
        'launcher',
        'modprobe',
        'dnf',
        'gdm-x-session',
        'systemd-udevd',
        'gdm-session-wor',
        'systemd-userwor',
        'fprintd',
        'systemd',
        'gpg-agent',
        'systemd-userdbd',
        'nginx',
        'sshd',
        'zfs',
        'ssh',
        'sedispatch',
        'zypak-sandbox'
      )
      AND NOT cmdline LIKE '%--type=zygote%'
      AND NOT cmdline LIKE '%--disable-seccomp-filter-sandbox%'
      AND NOT cgroup_path LIKE '/system.slice/docker-%'
      AND NOT cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%'
      AND NOT (
        name LIKE 'systemd-%'
        AND parent = 1
      )
      AND NOT (
        name = 'sh'
        AND cgroup_path = '/system.slice/znapzend.service'
      )
  )
  AND NOT p1.name IN ('systemd-userdbd')
  AND NOT p1.cmdline LIKE 'bwrap %'
GROUP BY p0.pid
HAVING env_count == 0;