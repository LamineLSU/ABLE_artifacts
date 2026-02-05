rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 05 6A 00 50 68 50 80 5A 00 51 6A 00 90 E8 F4 82 98 75 }
        $pattern1 = { 85 C0 74 06 E8 61 2E 7C 04 90 E8 EF 0F 00 00 }
        $pattern2 = { 6A 00 90 E8 34 6F 88 74 CC CC CC CC }

    condition:
        any of them
}