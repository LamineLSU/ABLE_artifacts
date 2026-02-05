rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 57 53 56 57 33 FF 57 6A 40 BE 00 30 00 00 56 68 D0 07 00 00 57 FF 15 94 37 38 00 }
        $pattern1 = { 85 C0 75 07 57 FF 15 BC 36 38 00 6A 04 56 BE C0 41 C8 17 56 57 FF 15 EC 36 38 00 }
        $pattern2 = { 55 8B EC 51 53 56 57 33 FF 57 6A 40 BE 00 30 00 00 56 68 D0 07 00 00 57 FF 15 94 37 38 00 }

    condition:
        any of them
}