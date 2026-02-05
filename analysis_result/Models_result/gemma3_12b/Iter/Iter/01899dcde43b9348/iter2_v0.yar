rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x00D0617A+0,action0=skip,bp1=0x00D061D2+0,action1=skip,bp2=0x00D061F1+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 33 DB BA 21 05 00 }
        $pattern2 = { 50 FF 15 88 A0 D0 00 }

    condition:
        any of them
}