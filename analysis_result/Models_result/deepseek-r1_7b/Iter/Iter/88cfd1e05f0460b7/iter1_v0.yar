rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific sequences from the trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 8D 95 F0 FE FF FF EA EA DD EB 00 00 01 10 EC 8B 46 20 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}