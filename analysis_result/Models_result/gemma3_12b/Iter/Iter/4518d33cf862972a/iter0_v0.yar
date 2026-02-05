rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B D0 E8 7D AE 00 00 85 C0 75 1D }
        $pattern1 = { FF 15 44 74 EA 00 50 FF 15 14 75 EA 00 85 C0 75 07 }
        $pattern2 = { 53 56 57 33 DB 53 6A 40 }

    condition:
        any of them
}