rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 08 3D 3F 03 8D 4C 24 1C E8 D2 CD FF FF }
        $pattern1 = { 8D 4C 24 5C E8 6D 12 00 00 59 50 8D 4C 24 30 E8 C8 02 00 00 }
        $pattern2 = { 6A 01 5A 8B CE E8 74 05 00 00 58 5E 8B }

    condition:
        any of them
}