rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 51 53 56 57 33 FF }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern2 = { 83 F8 11 74 05 8B C0 }

    condition:
        any of them
}