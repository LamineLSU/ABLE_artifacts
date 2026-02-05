rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 7B 28 01 EB 28 00 00 00 01 75 03 E0 00 40 67 8F FF 53 24 CA EB 24 }
        $pattern1 = { 80 7B 28 01 EB 28 00 00 00 00 74 07 00 40 67 9C 8B C3 EA EB E8 96 FB FF CA 63 1C }
        $pattern2 = { B9 0C 00 00 00 EC 00 00 00 0C F3 A5 EB E9 67 FF FF 00 40 67 34 }

    condition:
        any of them
}