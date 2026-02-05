rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 57 56 FF 15 94 37 61 00 50 FF 15 58 37 61 00 85 C0 75 07 }
        $pattern1 = { 6A 40 BE 00 30 00 00 56 68 D0 07 00 00 57 FF 15 94 37 61 00 }
        $pattern2 = { FF 15 BC 36 61 00 6A 04 56 57 6A 40 BE 00 30 00 00 56 }

    condition:
        any of them
}