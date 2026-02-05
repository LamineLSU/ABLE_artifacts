rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 00 00 }
        $pattern1 = { 6A 5A 0B F8 ?? ?? }
        $pattern2 = { C3 00 07 FF 19 68 F4 FF 5C 0D FF 04 00 }

    condition:
        any of them
}