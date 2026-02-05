rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern3+0,action2=skip,bp3=$pattern2+0,action3=skip,count=0"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { E8 25 05 00 00 85 C0 }
        $pattern3 = { 03 C3 BA 04 01 00 }

    condition:
        any of them
}