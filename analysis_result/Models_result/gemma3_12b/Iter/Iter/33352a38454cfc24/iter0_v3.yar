rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 8B 48 08 }
        $pattern1 = { 50 FF 15 7C 70 2D 01 50 FF 15 40 70 2D 01 }
        $pattern2 = { FF 15 B0 70 2D 01 50 FF 15 7C 70 2D 01 }

    condition:
        any of them
}