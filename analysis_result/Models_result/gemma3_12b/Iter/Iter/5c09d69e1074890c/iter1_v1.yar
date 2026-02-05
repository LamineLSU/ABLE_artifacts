rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 8B 48 14 8B 06 83 C4 14 52 5D }
        $pattern2 = { 6A 05 5A 8B CE E8 0C 00 00 00 85 C0 }

    condition:
        any of them
}