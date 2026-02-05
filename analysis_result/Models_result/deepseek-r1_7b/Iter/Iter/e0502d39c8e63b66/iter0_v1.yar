rule Bypass_Sample
{
    meta:
        description = "Evasion bypass by skipping function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 8D 45 ?? ?? ?? }
        $pattern1 = { 75 CC ?? ?? ?? ?? }
        $pattern2 = { FF 3F 8B 00 0F 84 ?? ?? ?? }

    condition:
        any of them
}