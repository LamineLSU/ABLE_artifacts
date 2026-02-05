rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 94 FD FF FF E8 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 8B 4D FC }
        $pattern2 = { E8 ?? ?? ?? ?? 8B 55 FC }

    condition:
        any of them
}