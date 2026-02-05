rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { E8 74 0A 00 00 8B 55 14 8B 45 10 8B 4D 0C 83 C4 14 }
        $pattern2 = { 6A 35 6A 00 51 50 E8 74 0A 00 00 8B 55 0C 0C 8B }

    condition:
        any of them
}