rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting early execution points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0xE8 ?? ?? ?? ?? }
        $pattern1 = { 0x6A ?? ?? 0x5A ?? ?? ?? }
        $pattern2 = { 0x8B 0xCE ?? ?? ?? ?? }

    condition:
        any of them
}