rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns for sandbox VM evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 D1 FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 59 ?? ?? FF 74 24 04 ?? ?? 8B EC E8 ?? }
        $pattern2 = { FF 74 24 04 ?? ?? ?? E8 F7 25 00 00 74 59 ?? }

    condition:
        any of them
}