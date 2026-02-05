rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { AD 77 B8 0A 04 B6 6F C1 84 81 6A 00 55 8B EC }
        $pattern2 = { 6A 36 6A 00 51 8D B0 7C 0C 00 00 56 50 }

    condition:
        any of them
}