rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 E9 04 77 F1 01 CF AD ED EC E9 4C FF FF FF FF 5E 89 F7 B9 00 4C 00 00 EB 23 }
        $pattern1 = { 8B 5F 04 8D 84 30 00 E0 00 00 01 F3 50 83 C7 08 FF 96 28 E0 00 00 95 8A 07 47 08 C0 }
        $pattern2 = { FF 96 2C E0 00 00 83 C7 04 8D 5E FC 31 C0 8A 07 47 09 C0 74 22 3C EF 77 11 }

    condition:
        any of them
}