rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 10 EA 32 ?? ?? ?? ?? }
        $pattern1 = { 83 F8 01 74 EA ED ?? }
        $pattern2 = { 3D 00 10 00 00 EA 00 00 00 00 ?? ?? }
}

condition:
    (any of them)