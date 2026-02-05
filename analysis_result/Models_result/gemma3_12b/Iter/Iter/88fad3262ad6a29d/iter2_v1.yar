rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B }
        $pattern1 = { 8B 35 AC F1 47 00 68 E7 03 00 00 }
        $pattern2 = { 6A 00 FF 15 0C F2 47 00 }

    condition:
        any of them
}