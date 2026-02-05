rule ExitBypass
{
    meta:
        description: "Evasion bypass detection"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { FF D2 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}