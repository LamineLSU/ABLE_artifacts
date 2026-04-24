rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? 8B CE }
        $pattern1 = { CA 74 ?? ?? 8D 95 F0 FE FF }
        $pattern2 = { EA 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}