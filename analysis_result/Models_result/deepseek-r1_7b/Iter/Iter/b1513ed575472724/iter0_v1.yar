rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 F7 25 00 00 A8 01 } // This pattern captures the first bypass candidate with a specific offset
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? } // This pattern captures another bypass candidate with different instruction sequence

    condition:
        any of them
}