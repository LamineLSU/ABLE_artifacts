rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass targeting ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 8B EC E8 C8 FF }  // Skips pushing ebp
        $pattern1 = { 55 8B EC ?? E7 F3 }  // Skips mov ebp, esp and pushes dword ptr
        $pattern2 = { E7 F3 ?? ?? E7 FB ?? }   // Bypasses call by using incorrect offset or displacement

    condition:
        any of them
}