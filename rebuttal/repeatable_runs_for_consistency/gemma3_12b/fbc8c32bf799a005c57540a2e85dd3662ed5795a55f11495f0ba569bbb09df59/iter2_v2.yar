rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 81 F8 00 00 00 74 0A 83 C4 05 85 C0 }
        $pattern1 = { 6A 05 6A 00 50 68 50 80 85 00 51 6A 00 FF 15 C8 81 85 00 }
        $pattern2 = { 85 C0 74 0A E8 B1 28 00 00 81 F8 00 00 00 74 0A }

    condition:
        any of them
}