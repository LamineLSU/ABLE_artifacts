rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved to target specific bypass sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 20 FF EE CE 81 FF 99 02 00 00 00 ?? }
        $pattern2 = { 20 FF EE CE 85 C1 0F 84 ?? ?? ?? ?? 8B 46 FC }

    condition:
        any of them
}