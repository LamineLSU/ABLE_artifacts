rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 0F 45 FC }
        $pattern1 = { E9 B5 FC 00 9D 62 07 F8 4B E8 0D 0C 00 00 C3 }
        $pattern2 = { 33 FF F8 D1 0F 45 FC }

    condition:
        any of them
}