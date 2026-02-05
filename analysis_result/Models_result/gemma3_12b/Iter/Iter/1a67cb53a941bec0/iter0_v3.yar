rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC E8 ?? ?? ?? ?? 59 FF 75 08 } // Bypass initial CALL (trace 1, 4, 5)
        $pattern1 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? 83 F8 ?? 74 ?? } // Bypass conditional jump (trace 5)
        $pattern2 = { 55 8B EC FF 75 08 FF 15 ?? ?? ?? ?? 59 } // Bypass push instruction (trace 5)

    condition:
        any of them
}