rule ExitProcessBypass {
    meta:
        description = "Evasion bypass for exit process in sandbox/VM"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 8B FF C4 ?? ?? 14 } 
        $pattern1 = { ?? 89 FF FD 3F 7E }
        $pattern2 = { ?? 8B 4E 45 0A 6A 00 ?? 8B EC ?? CA }

    condition:
        any of them
}