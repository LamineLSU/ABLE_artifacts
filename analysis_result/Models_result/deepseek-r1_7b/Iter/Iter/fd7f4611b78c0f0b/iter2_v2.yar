rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass detection for early exits"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 0F C4 }
        $pattern1 = { FF C8 ?? 00 59 ?? ?? ?? }
        $pattern2 = { FF 15 AC B0 ?? ?? 83 CC ?? }

    condition:
        any of them
}