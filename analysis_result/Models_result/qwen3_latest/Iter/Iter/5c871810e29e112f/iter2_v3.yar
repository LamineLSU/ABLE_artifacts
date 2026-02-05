rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 05 00 00 85 C0 74 ?? }  // Call to 0096667Fh followed by test and je
        $pattern1 = { E8 ?? FA FF FF 85 C0 0F 84 ?? FD FF FF }  // Call to 00965C17h followed by test and je
        $pattern2 = { FF 15 ?? A1 96 00 }  // Call to ExitProcess at 0096A12C

    condition:
        any of them
}