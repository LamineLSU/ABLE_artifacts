rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 33 DB BA 21 05 00 53 6A 40 53 68 04 1E 30 }
        $pattern2 = { B9 42 CE 30 E8 E3 FA FF FF }

    condition:
        any of them
}