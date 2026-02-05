rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0127617A+0,action0=skip,bp1=012761A3+0,action1=skip,bp2=012761D2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }
        $pattern2 = { 33 DB BA 21 05 00 00 53 6A 40 }

    condition:
        any of them
}