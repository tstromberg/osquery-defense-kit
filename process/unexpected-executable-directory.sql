SELECT p.pid,
    p.name,
    p.path,
    p.euid,
    p.gid,
    p.path AS fullpath,
    f.directory AS dirname,
    p.cmdline,
    hash.sha256
FROM processes p
    JOIN file f ON p.path = f.path
    JOIN hash ON hash.path = p.path -- NOTE: Everything after this is shared with process_events/unexpected-executable-directory-events
WHERE dirname NOT LIKE '/Applications/%.app/%'
    AND dirname NOT LIKE '/home/%'
    AND dirname NOT LIKE '/Library/Apple/System/Library%'
    AND dirname NOT LIKE '/Library/Java/JavaVirtualMachines/%'
    AND dirname NOT LIKE '/Library/Application Support/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/Audio/Plug-Ins/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/CoreMediaIO/Plug-Ins/%'
    AND dirname NOT LIKE '/Library/Internet Plug-Ins/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/Developer/CommandLineTools/%'
    AND dirname NOT LIKE '/Library/SystemExtensions/%'
    AND dirname NOT LIKE '/Library/Developer/%'
    AND dirname NOT LIKE '/nix/store/%/bin'
    AND dirname NOT LIKE '/nix/store/%/lib/%'
    AND dirname NOT LIKE '/nix/store/%/libexec'
    AND dirname NOT LIKE '/nix/store/%/libexec/%'
    AND dirname NOT LIKE '/nix/store/%/share/%'
    AND dirname NOT LIKE '/opt/%'
    AND dirname NOT LIKE '/opt/homebrew/%'
    AND dirname NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
    AND dirname NOT LIKE '/private/var/folders/%/Contents/Frameworks/%'
    AND dirname NOT LIKE '/private/var/folders/%/Contents/MacOS'
    AND dirname NOT LIKE '/private/var/folders/%/go-build%'
    AND dirname NOT LIKE '/tmp/go-build%'
    AND dirname NOT LIKE '/snap/%'
    AND dirname NOT LIKE '/System/%'
    AND dirname NOT LIKE '/Users/%'
    AND dirname NOT LIKE '/Users/%/Library/Application Support/%'
    AND dirname NOT LIKE '/usr/libexec/%'
    AND dirname NOT LIKE '/usr/local/%/bin/%'
    AND dirname NOT LIKE '/usr/local/%/dist'
    AND dirname NOT LIKE '/usr/local/%bin'
    AND dirname NOT LIKE '/usr/local/%libexec'
    and dirname NOT LIKE '/usr/local/Cellar/%'
    AND dirname NOT LIKE '/usr/lib/%'
    AND dirname NOT LIKE '/usr/lib64/%'
    AND dirname NOT LIKE '/private/var/folders/%/bin'
    AND dirname NOT LIKE '/private/var/folders/%/GoLand'
    AND dirname NOT LIKE '/tmp/%/bin'
    AND dirname NOT LIKE '/usr/local/go/pkg/tool/%'
    AND dirname NOT IN (
        '/bin',
        '/Library/DropboxHelperTools/Dropbox_u501',
        '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS',
        '/Library/Printers/DYMO/Utilities',
        '/Library/PrivilegedHelperTools',
        '/sbin',
        '/usr/bin',
        '/usr/lib',
        '/usr/lib/bluetooth',
        '/usr/lib/cups/notifier',
        '/usr/lib/evolution-data-server',
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
        '/usr/lib64/firefox',
        '/usr/libexec',
        '/usr/libexec/ApplicationFirewall',
        '/usr/libexec/rosetta',
        '/usr/sbin',
        '/usr/share/code'
    )
    AND fullpath NOT IN (
        '/usr/libexec/AssetCache/AssetCache',
        '/Library/PrivilegedHelperTools/com.adobe.acc.installer.v2',
        '/Library/PrivilegedHelperTools/com.adobe.ARMDC.Communicator',
        '/Library/PrivilegedHelperTools/com.adobe.ARMDC.SMJobBlessHelper',
        '/Library/PrivilegedHelperTools/com.docker.vmnetd',
        '/Library/PrivilegedHelperTools/com.macpaw.CleanMyMac4.Agent',
        '/Library/PrivilegedHelperTools/keybase.Helper',
        '/usr/lib/firefox/firefox',
        '/usr/lib64/firefox/firefox'
    )
    AND dirname NOT LIKE '/Library/%/%.bundle/Contents/Helpers'
    AND dirname NOT LIKE '/Library/%/Resources/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/Application Support/Adobe/%'
    AND dirname NOT LIKE '/Library/Developer/CommandLineTools/Library/%'
    AND NOT (
        dirname = ''
        AND name LIKE "runc%"
    ) -- Pulumi executables are often executed from $TMPDIR
    AND NOT (
        dirname LIKE "/private/var/%"
        AND p.name LIKE "pulumi-go.%"
    ) -- Chrome executes patches from /tmp :(
    AND NOT (
        dirname LIKE "/private/tmp/%"
        AND p.name = "goobspatch"
    )