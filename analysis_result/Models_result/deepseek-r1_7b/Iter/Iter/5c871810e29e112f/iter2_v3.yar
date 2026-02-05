rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted early checks and conditional logic"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? 8B 45 FC }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? 8B E5 }
        $pattern2 = { 3D 00 10 00 00 05 8B 45 FC }

    condition:
        any of them
}