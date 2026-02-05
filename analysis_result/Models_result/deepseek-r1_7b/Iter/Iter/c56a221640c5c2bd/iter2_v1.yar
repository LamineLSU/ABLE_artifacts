rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 5A 5E ?? ?? ?? }
        $pattern1 = { 79 FD ?? 5D ?? ?? ?? ?? }
        $pattern2 = { C3 FF 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}