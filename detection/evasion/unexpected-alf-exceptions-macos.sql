-- macOS application layer firewall (ALF) service exceptions.
--
-- false positives:
--   * locally built software
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  ae.path,
  ae.state,
  file.mtime,
  file.ctime,
  file.uid,
  file.directory,
  file.size,
  file.type,
  hash.sha256,
  signature.identifier,
  signature.authority,
  CONCAT (
    signature.authority,
    ',',
    signature.identifier,
    ',',
    ae.path,
    ',',
    MIN(file.uid, 501)
  ) AS exception_key
FROM
  alf_exceptions ae
  LEFT JOIN file ON ae.path = file.path
  LEFT JOIN hash ON ae.path = hash.path
  LEFT JOIN signature ON ae.path = signature.path
WHERE
  -- Filter out stock exceptions to decrease overhead
  ae.path NOT IN (
    '/System/Library/CoreServices/UniversalControl.app/',
    '/System/Library/PrivateFrameworks/Admin.framework/Versions/A/Resources/readconfig',
    '/System/Library/PrivateFrameworks/EmbeddedOSInstall.framework/Versions/A/XPCServices/EmbeddedOSInstallService.xpc/',
    '/usr/bin/nmblookup',
    '/usr/libexec/bootpd',
    '/usr/libexec/configd',
    '/usr/libexec/discoveryd',
    '/usr/libexec/xartstorageremoted',
    '/usr/sbin/mDNSResponder',
    '/usr/sbin/racoon'
  )
  AND exception_key NOT IN (
     ',a.out,/opt/homebrew/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin/kubectl,501',
    'Apple Mac OS Application Signing,com.apple.garageband10,/Applications/GarageBand.app/,0',
    'Apple Mac OS Application Signing,com.utmapp.QEMULauncher,/Applications/UTM.app/Contents/XPCServices/QEMUHelper.xpc/Contents/MacOS/QEMULauncher.app/,0',
    'Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension,/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/,0',
    ',,/Applications/Google%20Chrome.app/,',
    ',,/Applications/IntelliJ%20IDEA.app/,',
    ',,/Applications/ProtonMail%20Bridge.app/,',
    ',,/Applications/Visual%20Studio%20Code.app/,',
    ',,/Applications/Visual%20Studio%20Code.app/Contents/Frameworks/Code%20Helper.app/,',
    'Developer ID Application: Bohemian Coding (WUGMZZ5K46),com.bohemiancoding.sketch3,/Applications/Sketch.app/,501',
    'Developer ID Application: Bohemian Coding (WUGMZZ5K46),com.bohemiancoding.SketchMirrorHelper,/Applications/Sketch.app/Contents/XPCServices/SketchMirrorHelper.xpc/,501',
    'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW),com.brother.utility.WorkflowAppControlServer,/Library/Printers/Brother/Utilities/Server/WorkflowAppControl.app/,0',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5),com.elgato.WaveLink,/Applications/WaveLink.app/,0',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK),com.getdropbox.dropbox,/Applications/Dropbox.app/,501',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),com.jetbrains.goland,/Applications/GoLand.app/,501',
    'Developer ID Application: Opentest, Inc. (QGD2ZPXZZG),com.loom.desktop,/Applications/Loom.app/,501',
    'Developer ID Application: RescueTime, Inc (FSY4RB8H39),com.rescuetime.RescueTime,/Applications/RescueTime.app/,0',
    'Developer ID Application: Sonos, Inc. (2G4LW83Q3E),com.sonos.macController,/Applications/Sonos.app/,501',
    'Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.client,/Applications/Spotify.app/,501',
    'Developer ID Application: VNG ONLINE CO.,LTD (CVB6BX97VM),com.vng.zalo,/Applications/Zalo.app/,501',
    ',java,/opt/homebrew/Cellar/openjdk/19/libexec/openjdk.jdk/Contents/Home/bin/java,501',
    ',org.python.python,/opt/homebrew/Cellar/python@3.10/3.10.9/Frameworks/Python.framework/Versions/3.10/Resources/Python.app/,501',
    'Software Signing,com.apple.audio.InfoHelper,/System/Library/Frameworks/AudioToolbox.framework/XPCServices/com.apple.audio.InfoHelper.xpc/,0',
    'Software Signing,com.apple.controlcenter,/System/Library/CoreServices/ControlCenter.app/,0',
    'Software Signing,com.apple.Music,/System/Applications/Music.app/,0',
    'Software Signing,com.apple.nc,/usr/bin/nc,0',
    'Software Signing,com.apple.WebKit.Networking,/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/,0',
    'Software Signing,com.apple.WebKit.Networking,/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/,0',
    'Software Signing,com.apple.xartstorageremoted,/usr/libexec/xartstorageremoted,0',
    '/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/'
  )
  AND NOT exception_key LIKE ',node,/opt/homebrew/Cellar/nvm/%/versions/node/v%/bin/node,501'
  AND NOT exception_key LIKE  ',a.out,/opt/homebrew/Cellar/podman/%/libexec/podman/gvproxy,501'

  AND NOT (
    signature.identifier LIKE 'cargo-%'
    AND ae.path LIKE '/Users/%/.rustup/%'
  )
  AND NOT (
    signature.identifier LIKE 'fake-%'
    AND ae.path LIKE '%/exe/fake'
  )
  AND NOT (
    signature.identifier LIKE 'mariadbd-%'
    AND ae.path LIKE '/opt/homebrew/%/mariadbd'
  )
  AND NOT (
    signature.identifier = 'netcat'
    AND ae.path LIKE '/Users/%/homebrew/Cellar/netcat/%/bin/netcat'
  )
  AND NOT (
    signature.identifier = 'syncthing'
    AND ae.path LIKE '/nix/store/%-syncthing-%/bin/syncthing'
  )
  AND NOT (
    ae.path LIKE '/Users/%/Library/Application%20Support/Steam/Steam.AppBundle/Steam/'
  )
  AND NOT (
    signature.authority = ''
    AND signature.identifier = 'org.chromium.Chromium'
    AND ae.path LIKE '/Users/%/Library/pnpm/global/%/.pnpm/carlo@%/node_modules/carlo/lib/.local-data/mac-%/chrome-mac/Chromium.app/'
  )
  AND NOT (
    (
      signature.identifier = 'a.out'
      OR signature.identifier LIKE '%-%'
    )
    AND file.uid > 500
    AND (
      file.directory LIKE '/opt/homebrew/Cellar/%/bin'
      OR file.directory LIKE '/Users/%/bin'
      OR file.directory LIKE '/Users/%/code/%'
      OR file.directory LIKE '/Users/%/src/%'
      OR file.directory LIKE '/Users/%/sigstore/%'
      OR file.directory LIKE '/Users/%/node_modules/.bin/%'
      OR file.directory LIKE '/Users/%/git/%'
      OR file.directory LIKE '/Users/%/%-cli'
      OR file.directory LIKE '/private/var/folders/%/T/go-build%/exe'
    )
  )
GROUP BY
  exception_key
