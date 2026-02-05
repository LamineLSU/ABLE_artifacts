rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 45 FC }
        $pattern1 = { 8B 4D FC 5F 5E 33 CD }
        $pattern2 = { 85 C0 0F 84 33 FD FF FF }

    condition:
        any of them
}