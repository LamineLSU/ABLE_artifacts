rule Bypass_Evasion
{
    meta:
        description = "Program evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF C8 F0 00 00 ?? 40 E7 C3 }
        $pattern2 = { E8 C8 F0 00 00 ?? 40 E7 C3 }

    condition:
        any of them
}