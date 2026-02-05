rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 65 E8 00 8D 45 BC }
        $pattern1 = { 56 8A 01 84 C0 75 F5 }
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }

    condition:
        any of them
}