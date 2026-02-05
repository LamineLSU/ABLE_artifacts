rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting call instructions with memory/displacement"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 59 FF 75 08 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { 8B FF 55 8B EC FF 75 08 59 FF 75 08 ?? ?? ?? ?? C0 ?? }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 59 FF 75 08 ?? ?? ?? ?? 45 ?? }

    condition:
        any of them
}