rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using function calls with specific offsets"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 05 00 00 } // Bypass through first function call
        $pattern1 = { 8D ?? ?? ?? ?? FC 00 00 } // Bypass through second function call
        $pattern2 = { E8 ?? ?? ?? ?? 1A ?? } // Bypass through third function call

    condition:
        any of them
}