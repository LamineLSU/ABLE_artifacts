rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 } // test+je+push+mov+call
        $pattern1 = { E8 25 05 00 00 8B CE E8 74 FA FF FF } // call+mov+call (variant)
        $pattern2 = { 85 C0 74 07 50 FF 15 2C A1 B8 00 } // test+je+push+exit_call

    condition:
        any of them
}