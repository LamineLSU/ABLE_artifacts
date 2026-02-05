rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using specific sequences in the trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 3D 00 10 00 00 0F 82 EA AD EC DA }
        $pattern2 = { 74 12 8B 4D F8 CD AC EC BE EE }

    condition:
        any of them
}