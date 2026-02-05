rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern1 = { 68 40 11 A3 00 33 C9 E8 4B 17 00 00 A1 88 85 A3 00 85 C0 }
        $pattern2 = { FF 15 2C A1 A3 00 33 FF 8B C7 EB 03 8D 43 01 5F 5E 33 CD }

    condition:
        any of them
}