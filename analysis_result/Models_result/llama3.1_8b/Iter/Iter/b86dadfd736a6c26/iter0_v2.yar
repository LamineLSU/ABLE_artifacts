rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 4F FF FF FF ?? ?? ?? ?? ?? CA 00 41 09 30 }
        $pattern1 = { EB E9 ?? ?? ?? ?? ?? 00 41 09 C5 }
        $pattern2 = { E8 2C 01 00 00 ?? ?? ?? ?? ?? CA 00 41 0B 14 }

    condition:
        any of them
}