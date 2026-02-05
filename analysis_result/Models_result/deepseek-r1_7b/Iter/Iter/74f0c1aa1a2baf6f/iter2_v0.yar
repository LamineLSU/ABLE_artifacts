rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting specific exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { ??:68?? ... ??:68?? } (Exact push sequence from trace)
        $pattern2 = { ??:68?? ... ?? ?? ?? } (Exact push sequence from trace)

    condition:
        any of them
}