rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific exit decision check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 89 45 D0 ?? ?? ?? ?? ?? E8 F3 08 00 00 ?? ?? ?? ?? }
        $pattern1 = { 6A 01 FF 75 D0 FF 75 D0 E8 F7 08 00 00 }
        $pattern2 = { 89 45 E0 ?? ?? ?? ?? C7 45 F0 06 00 ?? FF 75 FC ?? }

    condition:
        any of them
}