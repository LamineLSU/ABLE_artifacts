rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific sequences for test+je"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? 00 B8 61 90 ?? } // test+je at offset
        $pattern1 = { 3D 00 10 00 00 0F 82 } // specific comparison value
        $pattern2 = { 85 C0 ?? ?? ?? ?? 74 12 ?? ?? ?? } // broader match for test+je

    condition:
        any of them
}