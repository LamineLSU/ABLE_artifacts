rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B C0 85 C9 }
        $pattern1 = { 55 8B EC 51 53 56 57 33 FF 57 6A 40 }
        $pattern2 = { 55 8B EC 83 E4 F8 83 EC 40 6A 40 33 C0 59 }

    condition:
        any of them
}