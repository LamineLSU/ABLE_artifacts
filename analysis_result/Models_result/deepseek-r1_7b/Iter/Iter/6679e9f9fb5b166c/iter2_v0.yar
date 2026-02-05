rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting known eviction points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 55 C3 FE FF ?? ?? ?? ?? }
        $pattern1 = { E8 D9 CE FF FF ?? ?? ?? ?? }
        $pattern2 = { E8 D6 CC FF FF ?? ?? ?? ?? }

    condition:
        any of them
}