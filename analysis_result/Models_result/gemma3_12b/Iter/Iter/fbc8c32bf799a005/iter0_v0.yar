rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 0C 36 F7 D1 01 F1 21 D1 }
        $pattern1 = { 51 6A 00 FF 15 C8 81 85 00 }
        $pattern2 = { 6A 00 FF 15 A4 81 85 00 }

    condition:
        any of them
}