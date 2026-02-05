rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 08 3D 3F 03 53 50 8D 4C 24 18 E8 38 F5 FF FF }
        $pattern1 = { 83 F8 20 7E 07 }
        $pattern2 = { 8D 4C 24 5C E8 6D 12 00 00 59 50 8D 4C 24 2C E8 C8 02 00 00 }

    condition:
        any of them
}