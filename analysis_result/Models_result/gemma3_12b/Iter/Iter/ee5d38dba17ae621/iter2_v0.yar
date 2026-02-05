rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x41E1B4,action0=skip,bp1=0x41E1D1,action1=skip,bp2=0x41E1F4,action2=skip,count=0"

    strings:
        $pattern0 = { 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 6A 35 6A 00 51 50 }
        $pattern2 = { 50 51 51 FF D2 5E 5E }

    condition:
        any of them
}