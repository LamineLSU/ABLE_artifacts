rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting multiple strategic points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A E8 25 05 00 00 8B 45 FC }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 CC 91 }
        $pattern2 = { 8A 61 EC FF FF 7E 74 07 E8 EC 12 07 0C 5C }

    condition:
        any of them
}