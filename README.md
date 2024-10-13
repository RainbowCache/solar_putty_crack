# Solar PuTTY Crack
Cracks Solar PuTTY session files. It attempts to brute force passwords for Solar PuTTY session files.

Usage: sp_crack <wordlist_filepath> <session_filepath>

There's a linux binary available to download in releases. You need mono / .net installed.

See https://hackmd.io/@tahaafarooq/cracking-solar-putty for an in-depth explanation of solar putty session data decrypting.

Example: 

    sp_crack /usr/share/wordlists/rockyou.txt ./session.dat

Example Output (Note, real output will not have CENSORED tags):

    Current platform cannot try to decrypt session data without password: Operation is not supported on this platform.
    This is expected on Linux and MacOS. Will continue to try to decrypt with password.
    Decrypted: {"Sessions":[{"Id":"<CENSORED>","Ip":"<CENSORED>","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"<CENSORED>","AuthenticateScript":"00000000-0000-0000-0000-000000000000","LastTimeOpen":"0001-01-01T00:00:00","OpenCounter":1,"SerialLine":null,"Speed":0,"Color":"#FF176998","TelnetConnectionWaitSeconds":1,"LoggingEnabled":false,"RemoteDirectory":""}],"Credentials":[{"Id":"<CENSORED>","CredentialsName":"root","Username":"root","Password":"<CENSORED>,"PrivateKeyPath":"","Passphrase":"","PrivateKeyContent":null}],"AuthScript":[],"Groups":[],"Tunnels":[],"LogsFolderDestination":"C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\Sessio
    Password founnd: <CENSORED>

