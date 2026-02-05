rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns for sandbox analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { FF 75 08 55 ?? ?? ?? ?? E8 C8 FF FF FF ?? }
        $pattern2 = { FF 75 08 59 ?? ?? ?? ?? }

    condition:
        any of them
}