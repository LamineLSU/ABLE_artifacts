rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 45 FC }
        $pattern1 = { 3D 00 10 00 00 00 0F 82 }
        $pattern2 = { 83 F8 01 74 12 8B 8B 4D FC }

    condition:
        any of them
}