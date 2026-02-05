rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern0+6,action1=skip,bp2=$pattern0+12,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}