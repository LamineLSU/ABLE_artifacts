rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 0x25 0x05 ?? ?? ?? ?? }
        $pattern1 = { E9 0x34 ?? ?? ?? ?? ?? ?? }
        $pattern2 = { E8 0x6A ?? ?? ?? ?? }

    condition:
        any of them
}