rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0041E1AF,action0=skip,bp1=0x0041E1D1,action1=skip,bp2=0x0041E1F0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E }
        $pattern1 = { 6A 35 6A 35 6A 00 6A 00 51 51 }
        $pattern2 = { 50 50 51 51 FF D2 5E }

    condition:
        any of them
}