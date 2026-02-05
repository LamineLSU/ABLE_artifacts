rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { F3 AA 8B 45 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8B 44 24 08 50 8B 42 40 83 C4 14 E8 DE FE FF FF }
        $pattern2 = { 3B 44 24 10 75 08 6A 00 }

    condition:
        any of them
}