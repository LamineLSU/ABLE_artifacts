rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns for sandbox detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 08 EC ?? ?? 8B FF 55 ?? ?? ?? FF 75 08 }
        $pattern1 = { 08 FB ?? ?? FF 75 08 FF 75 08 5A 8B CE E8 ?? ?? ?? ?? E8 C8 FF FF FF }
        $pattern2 = { ?? ?? ?? E8 C8 FF FF FF FF 75 08 FF 75 08 59 }
    condition:
        any of them
}