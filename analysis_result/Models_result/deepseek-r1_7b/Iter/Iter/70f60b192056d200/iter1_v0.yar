rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? 3D 00 00 00 00 }
        $pattern1 = { 83 F8 01 74 12 8B 4D FC ?? ?? ?? ?? ?? }
        $pattern2 = { 3D 00 00 00 00 00 00 00 59 EC }

    condition:
        any of them
}