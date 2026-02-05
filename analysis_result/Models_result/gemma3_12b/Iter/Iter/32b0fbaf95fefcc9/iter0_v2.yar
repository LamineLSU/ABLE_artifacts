rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Conditional Jump Bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 F6 74 18 8B 35 5C 04 51 00 } // test esi, esi; jz; mov esi, dword ptr [0051045Ch]

    condition:
        any of them
}