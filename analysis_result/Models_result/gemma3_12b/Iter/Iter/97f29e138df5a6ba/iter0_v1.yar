rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 83 EC 08 48 83 C4 01 50 48 89 C3 }
        $pattern1 = { E8 83 3C 1D 04 48 89 E0 8D 4C 24 18 }
        $pattern2 = { 0F B6 54 04 90 89 C6 21 D6 09 C2 }

    condition:
        any of them
}