rule Bypass_Sample_Corrected
{
    meta:
        description = "Evasion bypass rule - Trace 1, Call with Offset"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? FA FF FF 85 C0 0F 84 ?? FD FF FF }
        $pattern2 = { 6A ?? 53 68 ?? ?? ?? 01 33 C9 E8 ?? ?? ?? ?? }

    condition:
        any of them
}