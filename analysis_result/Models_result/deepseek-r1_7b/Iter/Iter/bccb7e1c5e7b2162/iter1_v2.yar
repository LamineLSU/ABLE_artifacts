rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific call and conditional patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern1 = { E8 74 FA FF FF ?? ?? ?? ?? ?? 00 01 E9 40 ?? ?? }
        $pattern2 = { 00 00 01 04 00 00 01 08 }

    condition:
        any of them
}