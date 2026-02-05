rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns for sandbox"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 1C 27 47 00 5A FF 15 F4 63 45 00 85 C0 FF D0 ?? ?? ?? ?? 50 FF 74 24 04 }
        $pattern1 = { 68 1C 27 47 00 5A FF 15 F4 63 45 00 85 C0 FF 74 24 04 FF 15 F8 63 45 00 85 C0 FF D0 }
        $pattern2 = { 68 1C 27 47 00 5A FF 15 F8 63 45 00 85 C0 FF 74 24 04 FF 15 8C 62 45 00 }

    condition:
        any of them
}