rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting function calls before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 E1 D0 8B 55 14 EA DD EB 14 8B 55 14 EA DD EB 14 E8 74 0A 00 00 CA 00 41 EB 27 }
        $pattern1 = { 00 41 E1 D5 EC 8D B0 98 0C 00 00 EA ED EA 00 00 0C 98 8D B0 98 0C 00 00 EA ED EA 00 00 0C 98 }
        $pattern2 = { 00 41 E1 EC AD 83 C4 14 AD 14 }

    condition:
        any of them
}