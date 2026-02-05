rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted setup instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A E8 CE ?? }
        $pattern1 = { 33 DB 53 BA 21 05 00 E8 E3 FF FF }
        $pattern2 = { 74 07 50 FF 15 2C A1 CB 00 E8 FF }
    condition:
        any of them
}