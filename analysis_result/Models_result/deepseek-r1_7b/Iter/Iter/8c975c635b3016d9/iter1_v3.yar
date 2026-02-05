rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using specific call instruction patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 ?? 45 ?? }
        $pattern1 = { E8 CE 74 0F 84 FF C8 ?? CC ?? }
        $pattern2 = { E8 C8 FF 15 AC B0 41 00 ?? ?? }

    condition:
        any of them
}