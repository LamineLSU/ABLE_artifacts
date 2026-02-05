rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 65 F8 00 53 33 DB 56 43 83 7D F8 0B 0F 87 13 01 00 }
        $pattern1 = { 83 65 F8 00 53 33 DB 56 43 83 7D F8 0B 0F 85 F5 00 00 00 }
        $pattern2 = { 6A 00 58 68 10 68 26 00 50 }

    condition:
        any of them
}