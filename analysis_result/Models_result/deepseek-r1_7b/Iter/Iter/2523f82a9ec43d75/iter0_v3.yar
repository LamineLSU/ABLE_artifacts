rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting multiple defense points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ?? 55 ?? FF 75 08 E8 C8 FF FF FF ?? ?? FF 15 AC B0 41 00 } 
        $pattern1 = { 6A 5B ?? 5A ?? 8B CE E8 25 05 00 ?? ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 6A 40 ?? 53 ?? 68 40 11 92 00 ?? 33 CD ?? 5B ?? E8 57 26 00 ?? C3 }

    condition:
        any of them
}