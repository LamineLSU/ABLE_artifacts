rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific check function targeting"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? EA 08 00 9B 65 5A }
        $pattern1 = { E8 CD 3D 00 00 CA 00 9B A3 02 EA 01 00 9B 65 5A }
        $pattern2 = { 8B 40 68 ?? ?? ?? ?? EA 08 00 13 65 5A }

    condition:
        any of them
}