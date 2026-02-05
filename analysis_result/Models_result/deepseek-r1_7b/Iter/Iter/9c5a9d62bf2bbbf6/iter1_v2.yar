rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific conditional checks at start of trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? 74 12 00 08 61 90 }
        $pattern1 = { 00 08 61 B1 03 C3 00 08 61 BE ?? 00 08 A0 88 }
        $pattern2 = { 00 08 61 4D 5A 00 08 61 52 E8 45 00 08 A0 88 }

    condition:
        any of them
}