-- Unexpected programs communicating over non-HTTPS protocols (state-based)
--
-- This query is a bit awkward and hobbled due to the lack of osquery support
-- for looking up binary signatures in Linux.
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net
-- platform: linux
SELECT
  s.remote_address,
  s.remote_port,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  pp.path AS parent_path,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  p.cgroup_path,
  s.state,
  hash.sha256,
  -- This intentionally avoids file.path, as it won't join across mount namespaces
  CONCAT (
    MIN(s.remote_port, 32768),
    ',',
    s.protocol,
    ',',
    MIN(p.euid, 500),
    ',',
    REPLACE(
      REPLACE(
        REGEX_MATCH (p.path, '(/.*?)/', 1),
        '/nix',
        '/usr'
      ),
      '/snap',
      '/opt'
    ),
    '/',
    REGEX_MATCH (p.path, '.*/(.*?)$', 1),
    ',',
    MIN(f.uid, 500),
    'u,',
    MIN(f.gid, 500),
    'g,',
    p.name
  ) AS exception_key
FROM
  process_open_sockets s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON p.path = hash.path
WHERE
  protocol > 0
  AND s.remote_port > 0 -- See unexpected-https-client
  AND NOT (
    s.remote_port = 443
    AND protocol IN (6, 17)
  ) -- See unexpected-dns-traffic
  AND NOT (
    s.remote_port = 53
    AND protocol IN (6, 17)
  )
  AND s.remote_address NOT IN (
    '127.0.0.1',
    '::ffff:127.0.0.1',
    '::1',
    '::',
    '0.0.0.0'
  )
  AND s.remote_address NOT LIKE 'fe80:%'
  AND s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '::ffff:172.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '::ffff:10.%'
  AND s.remote_address NOT LIKE '::ffff:192.168.%'
  AND s.remote_address NOT LIKE 'fc00:%'
  AND p.path != ''
  AND NOT exception_key IN (
    '123,17,114,/usr/chronyd,0u,0g,chronyd',
    '123,17,500,/usr/chronyd,0u,0g,chronyd',
    '143,6,500,/app/thunderbird,u,g,thunderbird',
    '143,6,500,/usr/thunderbird,0u,0g,thunderbird',
    '19305,6,500,/opt/firefox,0u,0g,firefox',
    '19305,6,500,/usr/firefox,0u,0g,firefox',
    '19305,6,500,/usr/firefox,0u,0g,.firefox-wrappe',
    '22000,6,500,/usr/syncthing,0u,0g,syncthing',
    '22,6,0,/usr/ssh,0u,0g,ssh',
    '22,6,0,/usr/tailscaled,0u,0g,tailscaled',
    '22,6,500,/home/cargo,500u,500g,cargo',
    '22,6,500,/home/terraform,500u,500g,terraform',
    '22,6,500,/usr/cargo,0u,0g,cargo',
    '22,6,500,/usr/ssh,0u,0g,ssh',
    '3000,6,500,/opt/brave,0u,0g,brave',
    '3000,6,500,/opt/chrome,0u,0g,chrome',
    '32768,6,0,/usr/tailscaled,0u,0g,tailscaled',
    '32768,6,500,/usr/ssh,0u,0g,ssh',
    '3443,6,500,/opt/chrome,0u,0g,chrome',
    '3478,6,500,/opt/chrome,0u,0g,chrome',
    '3478,6,500,/opt/firefox,0u,0g,firefox',
    '3478,6,500,/usr/chrome,0u,0g,chrome',
    '3478,6,500,/usr/firefox,0u,0g,firefox',
    '4070,6,500,/app/spotify,u,g,spotify',
    '4070,6,500,/opt/spotify,0u,0g,spotify',
    '4070,6,500,/opt/spotify,500u,500g,spotify',
    '4070,6,500,/usr/spotify,0u,0g,spotify',
    '43,6,500,/usr/whois,0u,0g,whois',
    '4460,6,114,/usr/chronyd,0u,0g,chronyd',
    '5004,6,500,/opt/brave,0u,0g,brave',
    '5006,6,500,/opt/brave,0u,0g,brave',
    '500,/usr/htop,0u,0g,htop',
    '5228,6,500,/opt/chrome,0u,0g,chrome',
    '5228,6,500,/usr/chrome,0u,0g,chrome',
    '6443,6,500,/usr/kubectl,0u,0g,kubectl',
    '67,17,0,/usr/NetworkManager,0u,0g,NetworkManager',
    '8000,6,500,/opt/chrome,0u,0g,chrome',
    '8000,6,500,/usr/firefox,0u,0g,firefox',
    '80,6,0,/usr/applydeltarpm,0u,0g,applydeltarpm',
    '80,6,0,/usr/bash,0u,0g,mkinitcpio',
    '80,6,0,/usr/bash,0u,0g,sh',
    '80,6,0,/usr/bash,0u,0g,update-ca-trust',
    '80,6,0,/usr/cp,0u,0g,cp',
    '80,6,0,/usr/fc-cache,0u,0g,fc-cache',
    '80,6,0,/usr/find,0u,0g,find',
    '80,6,0,/usr/gpg,0u,0g,gpg',
    '80,6,0,/usr/kmod,0u,0g,depmod',
    '80,6,0,/usr/kubelet,u,g,kubelet',
    '80,6,0,/usr/ldconfig,0u,0g,ldconfig',
    '80,6,0,/usr/NetworkManager,0u,0g,NetworkManager',
    '80,6,0,/usr/packagekitd,0u,0g,packagekitd',
    '80,6,0,/usr/pacman,0u,0g,pacman',
    '80,6,0,/usr/python3.10,0u,0g,dnf',
    '80,6,0,/usr/python3.10,0u,0g,dnf-automatic',
    '80,6,0,/usr/python3.10,0u,0g,yum',
    '80,6,0,/usr/python3.11,0u,0g,dnf',
    '80,6,0,/usr/python3.11,0u,0g,yum',
    '80,6,0,/usr/tailscaled,0u,0g,tailscaled',
    '80,6,0,/usr/.tailscaled-wrapped,0u,0g,.tailscaled-wra',
    '80,6,0,/usr/wget,0u,0g,wget',
    '80,6,100,/usr/http,0u,0g,http',
    '80,6,105,/usr/http,0u,0g,http',
    '80,6,500,/app/signal-desktop,u,g,signal-desktop',
    '80,6,500,/app/spotify,u,g,spotify',
    '80,6,500,/app/thunderbird,u,g,thunderbird',
    '80,6,500,/home/mconvert,500u,500g,mconvert',
    '80,6,500,/home/steam,500u,100g,steam',
    '80,6,500,/home/steam,500u,500g,steam',
    '80,6,500,/home/steamwebhelper,500u,500g,steamwebhelper',
    '80,6,500,/home/terraform,500u,500g,terraform',
    '80,6,500,/opt/brave,0u,0g,brave',
    '80,6,500,/opt/chrome,0u,0g,chrome',
    '80,6,500,/opt/firefox,0u,0g,firefox',
    '80,6,500,/opt/spotify,0u,0g,spotify',
    '80,6,500,/opt/zoom,0u,0g,zoom',
    '80,6,500,/usr/chrome,0u,0g,chrome',
    '80,6,500,/usr/curl,0u,0g,curl',
    '80,6,500,/usr/firefox,0u,0g,firefox',
    '80,6,500,/usr/firefox,0u,0g,.firefox-wrappe',
    '80,6,500,/usr/gnome-software,0u,0g,gnome-software',
    '80,6,500,/usr/pacman,0u,0g,pacman',
    '80,6,500,/usr/python3.10,0u,0g,yum',
    '80,6,500,/usr/python3.11,0u,0g,abrt-action-ins',
    '80,6,500,/usr/rpi-imager,0u,0g,rpi-imager',
    '80,6,500,/usr/signal-desktop,0u,0g,signal-desktop',
    '80,6,500,/usr/thunderbird,0u,0g,thunderbird',
    '80,6,500,/usr/WebKitNetworkProcess,0u,0g,WebKitNetworkPr',
    '8080,6,500,/opt/chrome,0u,0g,chrome',
    '8080,6,500,/usr/firefox,0u,0g,firefox',
    '8080,6,500,/usr/python3.11,0u,0g,speedtest-cli',
    '8080,6,500,/usr/speedtest,500u,500g,speedtest',
    '8443,6,500,/opt/chrome,0u,0g,chrome',
    '8443,6,500,/usr/firefox,0u,0g,firefox',
    '8801,17,500,/app/zoom.real,u,g,zoom.real',
    '8801,17,500,/opt/zoom,0u,0g,zoom',
    '88,6,500,/usr/syncthing,0u,0g,syncthing',
    '993,6,500,/app/thunderbird,u,g,thunderbird',
    '993,6,500,/usr/evolution,0u,0g,evolution',
    '993,6,500,/usr/thunderbird,0u,0g,thunderbird'
  )
  AND NOT (
    p.name = 'java'
    AND p.cmdline LIKE '/home/%/.local/share/JetBrains/Toolbox/%'
    AND s.remote_port > 1024
    AND s.protocol = 6
    AND p.euid > 500
  )
  AND NOT (
    p.name = 'syncthing'
    AND f.filename = 'syncthing'
    AND s.remote_port > 1024
    AND s.protocol = 6
    AND p.euid > 500
  )
  AND NOT (
    p.name = 'steam'
    AND f.filename = 'steam'
    AND s.remote_port > 27000
    AND s.protocol = 6
    AND p.euid > 500
  )
  AND NOT (
    p.name = 'chrome'
    AND f.filename = 'chrome'
    AND s.remote_port > 5000
    AND s.protocol = 6
    AND p.euid > 500
  )
  -- TODO: Move this to a custom override overlay, as it is extremely obscure (small ISP)
  AND NOT (
    exception_key = '32768,6,500,/usr/ssh,0u,0g,ssh'
    AND s.remote_port = 40022
    AND s.remote_address = '104.131.84.33' -- gatekeeper.uservers.net
  )
  AND NOT (
    s.remote_port = 80
    AND (
      p.cgroup_path LIKE '/system.slice/docker-%'
      OR p.cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%'
    )
  )
GROUP BY
  p.cmdline
