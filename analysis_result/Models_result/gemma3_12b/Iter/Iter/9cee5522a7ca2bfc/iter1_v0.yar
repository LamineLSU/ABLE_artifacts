rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 E9 04 77 F1 01 CF E9 4C FF FF FF }
        $pattern1 = { 8B 5F 04 8D 84 30 00 E0 00 00 01 F3 50 }
        $pattern2 = { 8B 07 2C 02 75 0F 86 C4 C1 C0 10 }

    condition:
        any of them
}