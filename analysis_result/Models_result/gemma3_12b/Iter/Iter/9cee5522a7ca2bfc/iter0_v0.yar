rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 E9 04 77 F1 01 CF }
        $pattern1 = { 8B 5F 04 8D 84 30 00 E0 00 00 01 F3 }
        $pattern2 = { 86 C4 C1 C0 10 86 C4 29 F8 }

    condition:
        any of them
}