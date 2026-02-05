rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - shifted and refined"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { ?? EC ?? ?? E8 ?A 3E 00 00 06 80 8B 4D F8 }
        $pattern2 = { 8B 40 68 C1 E8 A8 01 74 12 8B 48 D8 }

    condition:
        any of them
}