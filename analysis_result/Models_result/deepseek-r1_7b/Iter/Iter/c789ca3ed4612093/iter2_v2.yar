rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting exit decision"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 ?? ?? ?? ?? C1 E8 08 ?? 01 }
        $pattern1 = { 3D 00 10 00 00 0F 82 ?? ?? ?? ?? ?? DC ?? ?? }
        $pattern2 = { 59 EC ?? ?? 04 01 00 00 C0 ?? 00 ?? }

    condition:
        any of them
}