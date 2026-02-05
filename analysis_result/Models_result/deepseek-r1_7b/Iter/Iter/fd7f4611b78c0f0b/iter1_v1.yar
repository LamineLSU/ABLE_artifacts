rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific call and stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5B E8 CE E8 C8 ?? FE 41 C1 }
        $pattern1 = { 7D A3 F0 E3 F0 E3 F0 E3 F0 E3 F0 E3 F0 E3 F0 E3 F0 E3 }
        $pattern2 = { FF ?? 5A 8B CE E8 4B 17 00 FE FF FF }

    condition:
        any of them
}