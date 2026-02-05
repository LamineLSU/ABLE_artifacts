rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? E8 1B 05 00 00 }
        $pattern1 = { 03 FF 8B C7 EB 03 ?? ?? ?? ?? ?? }
        $pattern2 = { 8D 95 F0 FE FF FF ?? ?? C9 6C 80 }
    
    condition:
        any of them
}