rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with more specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 00 ?? ?? ?? ?? 5E EB }
        $pattern1 = { 8B D0 E8 DA FD FF FF CA DD 00 41 21 5F }
        $pattern2 = { 68 B8 FF 15 B0 62 45 00 CA DD 00 45 62 B0 }

    condition:
        any of them
}