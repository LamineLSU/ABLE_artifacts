rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 5C E8 6D 12 00 00 59 50 8D 4C 24 58 E8 AB 00 00 00 }
        $pattern1 = { 8D 8C 24 A0 00 00 00 E8 AB 00 00 00 68 90 50 46 00 8D 4C 24 14 E8 8F CE FF FF }
        $pattern2 = { FF 15 7C 72 45 00 6A 01 33 DB 53 50 FF 15 80 72 45 00 6A 02 A3 44 0D 47 00 58 }

    condition:
        any of them
}