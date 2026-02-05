rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Bypass Indirect Call 3"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { 53 6A 40 53 68 40 11 A8 00 33 C9 E8 4B 17 00 00 A1 88 85 A8 00 }

    condition:
        any of them
}