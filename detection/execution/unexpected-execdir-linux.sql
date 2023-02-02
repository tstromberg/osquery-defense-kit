-- Programs running out of unexpected directories, such as /tmp (state-based)
--
-- references:
--   * https://blog.talosintelligence.com/2022/10/alchimist-offensive-framework.html
--
-- tags: transient process state rapid
-- platform: linux
SELECT -- Child
  p0.path AS p0_path,
  p0.name AS p0_name,
  REGEX_MATCH (p0.path, '(/.*)/', 1) AS p0_dir,
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
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE p0.pid IN (
    SELECT pid
    FROM processes
    WHERE path != ""
      AND REGEX_MATCH (path, '(/.*)/', 1) NOT IN (
        '/bin',
        '/sbin',
        '/usr/bin',
        '/usr/lib',
        '/opt/google/chrome',
        '/opt/spotify',
        '/usr/lib64/firefox',
        '/usr/lib/bluetooth',
        '/usr/lib/electron19/electron',
        '/usr/lib/zeitgeist',
        '/usr/lib/electron19',
        '/usr/lib/cups/notifier',
        '/usr/lib/evolution-data-server',
        '/usr/libexec',
        '/usr/lib/firefox',
        '/usr/lib/fwupd',
        '/usr/lib/ibus',
        '/usr/lib/libreoffice/program',
        '/usr/lib/polkit-1',
        '/usr/lib/slack',
        '/usr/lib/snapd',
        '/usr/lib/systemd',
        '/usr/lib/telepathy',
        '/usr/lib/udisks2',
        '/usr/lib/xorg',
        '/usr/sbin',
        '/usr/share/code',
        '/usr/share/spotify-client',
        '/usr/share/teams',
        '/usr/share/teams/resources/app.asar.unpacked/node_modules/slimcore/bin'
      )
      GROUP BY path
  )
  AND p0_dir NOT LIKE '/home/%'
  AND p0_dir NOT LIKE '/nix/store/%'
  AND p0_dir NOT LIKE '/opt/%'
  AND p0_dir NOT LIKE '/snap/%'
  AND p0_dir NOT LIKE '%/.terraform/providers/%'
  AND p0_dir NOT LIKE '/tmp/%/bin'
  AND p0_dir NOT LIKE '/tmp/go-build%'
  AND p0_dir NOT LIKE '/usr/local/%'
  AND p0_dir NOT LIKE '/var/lib/snapd/snap/snapd/%'
  AND p0_path NOT LIKE '/tmp/%/_output/%'
  AND p0_path NOT LIKE '/tmp/%/output/%'
  AND p0_path NOT LIKE '/tmp/terraform_%/terraform' -- Exclude processes running inside of containers
  AND NOT p0_cgroup LIKE '/system.slice/docker-%'
  AND NOT p0_cgroup LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%' -- Almost certain to be a local console user
  AND NOT (
    p0_cgroup LIKE '/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-Alacritty-%.scope'
    AND p0_dir LIKE '/tmp/%'
  )