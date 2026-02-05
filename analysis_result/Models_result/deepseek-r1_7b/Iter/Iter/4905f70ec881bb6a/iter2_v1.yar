rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass targeting conditional jumps and calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 F4 ?? ?? 7E ?? 8B 45 ?? }
        $pattern1 = { E8 A3 ?? ?? ?? 7C 8A 6A 9D 0A 00 00 }
        $pattern2 = { 6A ?? 5A 8B CE E8 C3 ?? F3 4E FE 3F }

    condition:
        any of them
}