rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 C3 01 07 01 01 02 }
        $pattern1 = { E8 F7 25 C0 0F 84 ?? 8B 45 C3 01 07 01 02 }
        $pattern2 = { 6A 5A 8B CE E8 F7 25 C0 }

    condition:
        any of them
}