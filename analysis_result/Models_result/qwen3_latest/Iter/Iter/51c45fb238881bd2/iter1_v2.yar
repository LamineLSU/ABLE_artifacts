rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 ?? ?? ?? ?? } // test eax, eax + jne (evasion check)
        $pattern1 = { FF 96 ?? ?? ?? ?? }        // call [esi+offset] (exit trigger)
        $pattern2 = { 80 7B 28 02 75 0E }        // cmp byte + jne (sandbox check)

    condition:
        any of them
}