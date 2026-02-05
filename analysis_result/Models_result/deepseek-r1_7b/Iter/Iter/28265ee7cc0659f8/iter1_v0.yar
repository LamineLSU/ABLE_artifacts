rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific before exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 5A E8 4B C5 E8 FF }
        $pattern2 = { 3D E8 57 26 00 FE }

    condition:
        any of them
}